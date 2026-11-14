"""Only validated database fields reach generated configuration. No shell execution."""
import os, subprocess, pathlib, tempfile
from fastapi import HTTPException
from store import rows
CONF=pathlib.Path('/etc/swanctl/conf.d/vpnaas.conf')
PUBLIC_IF=os.environ.get('VPNAAS_PUBLIC_IF','ens3')
PUBLIC_IP=os.environ.get('VPNAAS_PUBLIC_IP','203.0.113.10')
LAN_IF=os.environ.get('VPNAAS_LAN_IF','ens8')
LAN_IP=os.environ.get('VPNAAS_LAN_IP','10.10.7.14')
LAN_CIDR=os.environ.get('VPNAAS_LAN_CIDR','10.10.7.0/24')
# Full-tunnel users may reach the internet but never these non-public ranges
# (other than their own allowed_cidrs, accepted earlier). Includes the VIP pool.
NON_PUBLIC='{ 0.0.0.0/8, 10.0.0.0/8, 100.64.0.0/10, 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, 192.0.0.0/24, 192.0.2.0/24, 192.168.0.0/16, 198.18.0.0/15, 198.51.100.0/24, 203.0.113.0/24, 224.0.0.0/3 }'
FULL_MSS=1300

def full_dns():
    import ipaddress
    raw=os.environ.get('VPNAAS_FULL_DNS','1.1.1.1,8.8.8.8')
    servers=[str(ipaddress.IPv4Address(x.strip())) for x in raw.split(',') if x.strip()]
    if not 0<len(servers)<=4:raise ValueError('VPNAAS_FULL_DNS must list 1-4 IPv4 addresses')
    return servers

def is_full(user):
    return user.get('traffic_mode','split')=='full'

def run(args,timeout=20,input=None):
    result=subprocess.run(args,input=input,text=True,capture_output=True,timeout=timeout)
    if result.returncode:raise RuntimeError('VPN command failed')
    return result.stdout

def vip(user):
    from pool import network
    import ipaddress
    value=user.get('virtual_ip')
    if not value:raise HTTPException(409,'User VIP missing; migrate database first')
    addr=ipaddress.IPv4Address(value)
    if addr not in network() or addr in (network().network_address,network().broadcast_address):
        raise HTTPException(409,'Invalid persisted user VIP')
    return str(addr)

def render(connections,users):
    lines=['connections {']
    for c in connections:
        if not c['enabled']:continue
        i=c['id']
        lines.append(f'''site-{i} {{
 version = 2
 local_addrs = {PUBLIC_IP}
 remote_addrs = {c['remote_address']}
 proposals = aes256-sha256-modp2048,aes128-sha256-modp2048
 local {{ auth = psk
 id = {PUBLIC_IP}
 }}
 remote {{ auth = psk
 id = {c['remote_id']}
 }}
 children {{ net-{i} {{
 local_ts = {c['local_ts']}
 remote_ts = {c['remote_ts']}
 esp_proposals = aes256-sha256,aes128-sha256
 start_action = none
 dpd_action = clear
 }} }}
}}''')
    # strongSwan 6.0.1: ask for EAP identity before selecting a user policy.
    # This candidate MUST never authorize: local MSCHAPv2 cannot grant groups.
    # After authentication, strongSwan rejects it and matches the authenticated
    # EAP identity against the per-user candidates below (including their VIPs).
    if any(u['enabled'] for u in users):
        lines.append(f'''c2s-eap-discovery {{
 version = 2
 local_addrs = {PUBLIC_IP}
 remote_addrs = %any
 proposals = aes256-sha256-modp2048,aes128-sha256-modp2048
 fragmentation = yes
 send_cert = always
 unique = replace
 local {{ auth = pubkey
 certs = server.pem
 id = {PUBLIC_IP}
 }}
 remote {{ auth = eap-mschapv2
 eap_id = %any
 id = %any
 groups = vpnaas-no-such-group
 }}
}}''')
    for u in users:
        if not u['enabled']:continue
        i=u['id']
        local_ts='0.0.0.0/0' if is_full(u) else ','.join(u['allowed_cidrs'])
        lines.append(f'''user-{i} {{
 version = 2
 local_addrs = {PUBLIC_IP}
 remote_addrs = %any
 proposals = aes256-sha256-modp2048,aes128-sha256-modp2048
 pools = pool-{i}
 fragmentation = yes
 send_cert = always
 unique = replace
 local {{ auth = pubkey
 certs = server.pem
 id = {PUBLIC_IP}
 }}
 remote {{ auth = eap-mschapv2
 eap_id = {u['username']}
 id = %any
 }}
 children {{ c2s-{i} {{
 local_ts = {local_ts}
 remote_ts = dynamic
 esp_proposals = aes256-sha256,aes128-sha256
 dpd_action = clear
 }} }}
}}''')
    lines.append('}\npools {')
    for u in users:
        if not u['enabled']:continue
        dns=f"\n dns = {','.join(full_dns())}" if is_full(u) else ''
        lines.append(f"pool-{u['id']} {{ addrs = {vip(u)}{dns}\n }}")
    lines.append('}\nsecrets {')
    for c in connections:
        if c['enabled']:lines.append(f'ike-{c["id"]} {{ id-1 = {PUBLIC_IP}\n id-2 = {c["remote_id"]}\n secret = "{c["psk"]}"\n }}')
    for u in users:
        if u['enabled']:lines.append(f'eap-{u["id"]} {{ id = {u["username"]}\n secret = "{u["password"]}"\n }}')
    lines.append('}')
    return '\n'.join(lines)+'\n'

def firewall(connections,users,policies):
    from pool import network
    pool=str(network())
    lines=['table inet vpnaas {','chain users {']
    for u in users:
        if u['enabled']:
            if is_full(u):lines.append(f'ip saddr {vip(u)} ip daddr {pool} drop')
            for dest in u['allowed_cidrs']:lines.append(f'ip saddr {vip(u)} ip daddr {dest} accept')
            if is_full(u):
                lines.append(f'ip saddr {vip(u)} ip daddr {NON_PUBLIC} drop')
                lines.append(f'ip saddr {vip(u)} oifname "{PUBLIC_IF}" accept')
    full=[vip(u) for u in users if u['enabled'] and is_full(u)]
    lines+=['drop']
    lines+=['}', 'chain mss { type filter hook forward priority mangle; policy accept;']
    for u in users:
        if not u['enabled']:continue
        v=vip(u)
        lines.append(f'ip saddr {v} meta ipsec exists tcp flags & (syn|rst) == syn tcp option maxseg size > {FULL_MSS} tcp option maxseg size set {FULL_MSS}')
        lines.append(f'ip daddr {v} rt ipsec exists tcp flags & (syn|rst) == syn tcp option maxseg size > {FULL_MSS} tcp option maxseg size set {FULL_MSS}')
    for c in connections:
        if not c['enabled']:continue
        for source,dest,match in ((c['remote_ts'],c['local_ts'],'meta'),(c['local_ts'],c['remote_ts'],'rt')):
            lines.append(f'ip saddr {source} ip daddr {dest} {match} ipsec exists tcp flags & (syn|rst) == syn tcp option maxseg size > {FULL_MSS} tcp option maxseg size set {FULL_MSS}')
    lines+=['}', 'chain forward { type filter hook forward priority 0; policy drop;']
    lines+=['ct state established,related accept',
            f'ip saddr {pool} meta ipsec exists jump users',
            f'ip saddr {pool} drop']
    for c in connections:
        if c['enabled']:
            lines.append(f'ip saddr {c["remote_ts"]} ip daddr {c["local_ts"]} meta ipsec exists accept')
            lines.append(f'ip saddr {c["local_ts"]} ip daddr {c["remote_ts"]} accept')
    for p in policies:
        if p['enabled']:
            proto='' if p['protocol']=='all' else 'ip protocol '+p['protocol']+' '
            # C2S is intercepted above; broad global policy cannot bypass per-user permissions.
            lines.append(f'ip saddr {p["source_cidr"]} ip daddr {p["destination_cidr"]} {proto}accept')
    lines+=['}','chain nat { type nat hook postrouting priority srcnat; policy accept;',
            f'ip saddr {pool} ip daddr {LAN_CIDR} oifname "{LAN_IF}" snat to {LAN_IP}']
    lines+=[f'ip saddr {v} oifname "{PUBLIC_IF}" snat to {PUBLIC_IP}' for v in full]
    lines+=['}','}']
    text='\n'.join(lines)+'\n'
    if os.environ.get('VPNAAS_ROUTE_AUTO')=='1':
        from network import route_firewall
        text=route_firewall(text,users)
    return text

def atomic(path,text):
    path.parent.mkdir(parents=True,exist_ok=True)
    fd,name=tempfile.mkstemp(dir=path.parent)
    try:
        os.fchmod(fd,0o600)
        with os.fdopen(fd,'w') as f:f.write(text)
        os.replace(name,path)
    finally:
        if os.path.exists(name):os.unlink(name)

def vici_session():
    import vici
    return vici.Session()


def reload_config():
    # Replacing existing VICI entries preserves insertion order. Unload owned
    # configs (NOT SAs) so discovery is first even on an already-running daemon.
    session = vici_session()
    for name in session.get_conns().get('conns', []):
        label = name.decode() if isinstance(name, bytes) else name
        if label == 'c2s-eap-discovery' or any(
            label.startswith(prefix) and label[len(prefix):].isdigit()
            for prefix in ('user-', 'site-')
        ):
            session.unload_conn({'name': name})
    run(['swanctl','--load-all','--clear'])


def apply():
    from network import configuration_lock
    with configuration_lock():
        return _apply_locked()

def _apply_locked():
    connections,users,policies=rows('connections'),rows('users'),rows('policies')
    text=render(connections,users)
    rules=firewall(connections,users,policies)
    old=CONF.read_text() if CONF.exists() else 'connections {}\n'
    # Batch replacement is atomic and touches only our table.
    exists=subprocess.run(['nft','list','table','inet','vpnaas'],capture_output=True).returncode==0
    batch=('delete table inet vpnaas\n' if exists else '')+rules
    try:
        run(['nft','--check','-f','-'],input=batch)
        atomic(CONF,text)
        reload_config()
        run(['nft','-f','-'],input=batch)
        atomic(pathlib.Path('/opt/vpnaas/firewall.nft'),rules)
    except Exception:
        atomic(CONF,old)
        try:reload_config()
        except Exception:pass
        raise HTTPException(502,'VPN configuration apply failed; previous configuration restored')

def revoke(kind,ident):
    if kind not in ('users','connections') or os.environ.get('VPNAAS_DRY_RUN')=='1':return
    name=('user-' if kind=='users' else 'site-')+str(ident)
    # swanctl returns nonzero when no matching SA exists; idempotent revocation.
    result=subprocess.run(['swanctl','--terminate','--ike',name,'--timeout','5'],capture_output=True,text=True,timeout=8)
    if result.returncode and 'no matching' not in (result.stdout+result.stderr).lower():
        raise HTTPException(502,'Unable to revoke existing VPN session')

def status():
    from pool import network
    return {'pool_cidr':str(network()),'raw':run(['swanctl','--list-sas']), 'connections':run(['swanctl','--list-conns']),
            'pools':run(['swanctl','--list-pools']), 'backend':'strongSwan swanctl'}

def action(connection,operation):
    if operation=='initiate':
        if not connection['enabled']:raise HTTPException(409,'Connection disabled')
        args=['swanctl','--initiate','--child',f'net-{connection["id"]}','--timeout','12']
    else:args=['swanctl','--terminate','--ike',f'site-{connection["id"]}','--timeout','12']
    try:return {'ok':True,'output':run(args,timeout=18)}
    except Exception:raise HTTPException(502,'VPN action failed; inspect status and strongSwan journal')
