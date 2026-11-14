"""Conservative kernel-route reconciliation. No interface/DHCP management."""
import ipaddress, json, subprocess, os, re, fcntl
from contextlib import contextmanager

@contextmanager
def configuration_lock():
    with open('/run/vpnaas-apply.lock','a') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX)
        yield

def snapshot():
    return json.loads(subprocess.check_output(['ip','-j','-4','route','show','table','main'],timeout=5))

def public_interface(routes):
    defaults=[r for r in routes if r.get('dst')=='default' and r.get('dev')]
    return min(defaults,key=lambda r:r.get('metric',0))['dev'] if defaults else None

def private_route(cidr,routes,public):
    target=ipaddress.IPv4Network(cidr)
    candidates=[]
    for r in routes:
        if r.get('dst','default')=='default':continue
        try:net=ipaddress.IPv4Network(r['dst'])
        except ValueError:continue
        if not net.overlaps(target):continue
        dev=r.get('dev')
        if r.get('type','unicast')!='unicast' or not dev or dev==public or dev=='lo':return None
        if not re.fullmatch(r'[A-Za-z0-9_.:-]{1,15}',dev):return None
        if target.subnet_of(net):candidates.append((net.prefixlen,r.get('metric',0),dev))
    return sorted(candidates,key=lambda x:(-x[0],x[1]))[0][2] if candidates else None

def diagnostics(users):
    routes=snapshot(); public=public_interface(routes)
    cidrs=sorted({c for u in users if u['enabled'] for c in u['allowed_cidrs']})
    result=[{'cidr':c,'interface':private_route(c,routes,public),'ready':bool(private_route(c,routes,public))} for c in cidrs]
    return {'public_interface':public,'private_routes':result,'private_ready':all(x['ready'] for x in result),'mode':'kernel-route-auto'}

def route_firewall(text,users):
    from vpn import vip, PUBLIC_IF, PUBLIC_IP
    from pool import network
    pool=str(network())
    routes=snapshot(); public=public_interface(routes)
    text=text.replace(f'oifname "{PUBLIC_IF}"',f'oifname "{public or "__no_route__"}"')
    lines=text.splitlines(); out=[]; nat=[]
    for line in lines:
        if line.startswith(f'ip saddr {pool} ip daddr ') and ' snat to ' in line:continue
        if ' snat to ' in line:
            line=line.split(' snat to ')[0]+' masquerade'
        for u in users:
            if not u['enabled']:continue
            for cidr in u['allowed_cidrs']:
                grant=f'ip saddr {vip(u)} ip daddr {cidr} accept'
                if line==grant:
                    dev=private_route(cidr,routes,public)
                    line=f'ip saddr {vip(u)} ip daddr {cidr} '+(f'oifname "{dev}" accept' if dev else 'drop')
                    if dev:nat.append(f'ip saddr {vip(u)} ip daddr {cidr} oifname "{dev}" masquerade')
        out.append(line)
        if line.startswith('chain nat {'):out.extend(nat)
    # Recheck every outbound VPN packet before established-flow acceptance:
    # detached private routes must not leak an existing flow via public default.
    established='ct state established,related accept'
    out.remove(established)
    idx=out.index(f'ip saddr {pool} drop')+1
    out.insert(idx,established)
    return '\n'.join(out)+'\n'

def reconcile():
    from vpn import firewall, run, atomic
    from store import rows
    from pathlib import Path
    with configuration_lock():
        rules=firewall(rows('connections'),rows('users'),rows('policies'))
        path=Path('/opt/vpnaas/firewall.nft')
        exists=subprocess.run(['nft','list','table','inet','vpnaas'],capture_output=True).returncode==0
        if exists and path.exists() and path.read_text()==rules:return
        batch=('delete table inet vpnaas\n' if exists else '')+rules
        run(['nft','--check','-f','-'],input=batch)
        run(['nft','-f','-'],input=batch)
        atomic(path,rules)

if __name__=='__main__':reconcile()
