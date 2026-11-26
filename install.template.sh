#!/usr/bin/env bash
set -euo pipefail
# Edit these values, or pass environment variables. Empty = detect/preserve.
PUBLIC_IP="${PUBLIC_IP:-}"
PUBLIC_IF="${PUBLIC_IF:-}"
LAN_CIDR="${LAN_CIDR:-}"
LAN_IF="${LAN_IF:-}"
LAN_IP="${LAN_IP:-}"
FULL_DNS="${FULL_DNS:-}"
REGION="${REGION:-}"
TENANT_ID="${TENANT_ID:-}"
INSTANCE_ID="${INSTANCE_ID:-}"
# Numeric sysctl overrides; defaults fit a small VM, not throughput guarantees.
export TUNE_NET_CORE_RMEM_MAX="${TUNE_NET_CORE_RMEM_MAX:-16777216}"
export TUNE_NET_CORE_WMEM_MAX="${TUNE_NET_CORE_WMEM_MAX:-16777216}"
export TUNE_NET_CORE_RMEM_DEFAULT="${TUNE_NET_CORE_RMEM_DEFAULT:-1048576}"
export TUNE_NET_CORE_WMEM_DEFAULT="${TUNE_NET_CORE_WMEM_DEFAULT:-1048576}"
export TUNE_NET_CORE_OPTMEM_MAX="${TUNE_NET_CORE_OPTMEM_MAX:-65536}"
export TUNE_NET_CORE_NETDEV_MAX_BACKLOG="${TUNE_NET_CORE_NETDEV_MAX_BACKLOG:-16384}"
export TUNE_NET_IPV4_TCP_RMEM="${TUNE_NET_IPV4_TCP_RMEM:-4096 87380 16777216}"
export TUNE_NET_IPV4_TCP_WMEM="${TUNE_NET_IPV4_TCP_WMEM:-4096 65536 16777216}"
export TUNE_NET_NETFILTER_NF_CONNTRACK_MAX="${TUNE_NET_NETFILTER_NF_CONNTRACK_MAX:-262144}"
export TUNE_FS_FILE_MAX="${TUNE_FS_FILE_MAX:-2097152}"
export PUBLIC_IP PUBLIC_IF LAN_CIDR LAN_IF LAN_IP FULL_DNS REGION TENANT_ID INSTANCE_ID
[[ $EUID -eq 0 ]] || { echo 'Run as root' >&2; exit 1; }
. /etc/os-release
[[ $ID == debian && $VERSION_ID == 13 ]] || { echo 'Debian 13 required' >&2; exit 1; }
export DEBIAN_FRONTEND=noninteractive
umask 077
apt-get update
apt-get install -y --no-install-recommends ca-certificates curl openssl python3 python3-venv nftables iproute2 ethtool kmod charon-systemd strongswan-swanctl strongswan-pki libcharon-extra-plugins libcharon-extauth-plugins libstrongswan-extra-plugins libstrongswan-standard-plugins
install -d -m 700 /opt/vpnaas/backend /var/lib/vpnaas /etc/vpnaas /etc/swanctl/conf.d /etc/swanctl/private /etc/swanctl/x509 /etc/swanctl/x509ca /etc/swanctl/x509crl
# Back up state before configuration or schema changes; never expose credentials.
python3 - <<'BACKUP'
from pathlib import Path
import datetime, shutil, sqlite3, json, subprocess
root=Path('/var/backups/vpnaas')/datetime.datetime.now().strftime('%Y%m%dT%H%M%S.%f')
root.mkdir(parents=True,mode=0o700)
for source in ('/etc/vpnaas','/etc/swanctl','/etc/sysctl.d/99-vpn-tuning.conf','/etc/modules-load.d/vpnaas.conf','/var/lib/vpnaas/ca-key.pem'):
    p=Path(source)
    if p.exists():
        target=root/source.lstrip('/')
        target.parent.mkdir(parents=True,exist_ok=True)
        shutil.copytree(p,target) if p.is_dir() else shutil.copy2(p,target)
p=Path('/var/lib/vpnaas/data.sqlite3')
if p.exists():
    conn=sqlite3.connect(p)
    dest=sqlite3.connect(root/'data.sqlite3');conn.backup(dest);dest.close()
    legacy=[i for i,b in conn.execute("SELECT id,body FROM objects WHERE kind='users'") if not json.loads(b).get('virtual_ip')]
    conn.close()
    if legacy:
        subprocess.run(['systemctl','stop','vpnaas-reconcile.timer','vpnaas-api.service'],check=True)
        for ident in legacy:
            r=subprocess.run(['swanctl','--terminate','--ike','user-'+str(ident),'--timeout','5'],capture_output=True,text=True,timeout=10)
            if r.returncode and 'no matching' not in (r.stdout+r.stderr).lower():raise SystemExit('Cannot safely terminate legacy user session')
        print('Legacy VIP migration: user sessions terminated; reconnect after install')
print('Backup: '+str(root))
BACKUP
python3 - <<'CONFIG'
import os, json, subprocess, ipaddress, re
from pathlib import Path
path=Path('/etc/vpnaas/backend.env')
old=dict(line.split('=',1) for line in path.read_text().splitlines() if '=' in line) if path.exists() else {}
route=json.loads(subprocess.check_output(['ip','-j','-4','route','get','1.1.1.1']))[0]
main_routes=json.loads(subprocess.check_output(['ip','-j','-4','route','show','table','main']))
addresses=json.loads(subprocess.check_output(['ip','-j','-4','addr']))
default_devs={r.get('dev') for r in main_routes if r.get('dst')=='default' and r.get('dev')}
# Prefer an interface holding an actual global public IPv4 (handles multi-NIC OpenStack VMs
# where a private NIC has a lower-metric default route than the public NIC).
global_nics=[(a['ifname'],x) for a in addresses for x in a['addr_info'] if x.get('scope')=='global' and ipaddress.IPv4Address(x['local']).is_global and not ipaddress.IPv4Address(x['local']).is_private]
pub_choice=next(((d,x) for d,x in global_nics if d in default_devs), global_nics[0] if global_nics else None)
pub_if=pub_choice[0] if pub_choice else route['dev']
pub_ip=pub_choice[1]['local'] if pub_choice else (route.get('prefsrc') or route.get('src'))
private=[(a['ifname'],x) for a in addresses for x in a['addr_info'] if x.get('scope')=='global' and ipaddress.IPv4Address(x['local']).is_private and a['ifname']!=pub_if]
lan=private[0] if private else None
fallback={'PUBLIC_IP':pub_ip,'PUBLIC_IF':pub_if,'LAN_CIDR':str(ipaddress.IPv4Network(f"{lan[1]['local']}/{lan[1]['prefixlen']}",strict=False)) if lan else '192.0.2.0/24','LAN_IF':lan[0] if lan else pub_if,'LAN_IP':lan[1]['local'] if lan else pub_ip,'FULL_DNS':'1.1.1.1,8.8.8.8'}
values={k:os.environ.get(k) or old.get('VPNAAS_'+k) or v for k,v in fallback.items()}
for k in ('PUBLIC_IP','LAN_IP'): values[k]=str(ipaddress.IPv4Address(values[k]))
if not ipaddress.IPv4Address(values['PUBLIC_IP']).is_global:raise SystemExit('PUBLIC_IP must be actual public IPv4; set PUBLIC_IP explicitly for NAT deployments')
values['LAN_CIDR']=str(ipaddress.IPv4Network(values['LAN_CIDR'],strict=False))
if values['LAN_CIDR']=='0.0.0.0/0':raise SystemExit('LAN_CIDR cannot be default route')
for k in ('PUBLIC_IF','LAN_IF'):
    if not re.fullmatch(r'[a-zA-Z0-9_.:-]{1,15}',values[k]) or not Path('/sys/class/net',values[k]).exists():raise SystemExit('Invalid interface '+k)
values['FULL_DNS']=','.join(str(ipaddress.IPv4Address(x.strip())) for x in values['FULL_DNS'].split(','))
if not 1<=len(values['FULL_DNS'].split(','))<=4:raise SystemExit('Set 1-4 DNS servers')
extra_meta=''
for mk in ('REGION','TENANT_ID','INSTANCE_ID'):
    mv=os.environ.get(mk) or old.get('VPNAAS_'+mk) or ''
    if mv and re.fullmatch(r'[A-Za-z0-9_.-]{1,64}',mv):
        extra_meta+='VPNAAS_'+mk+'='+mv+'\n'
for opt_k in ('VPNAAS_POOL_ALLOW_CUSTOM','VPNAAS_PUBLIC_DOCS','VPNAAS_SESSION_LIMIT'):
    if old.get(opt_k) in ('0','1'):
        extra_meta+=opt_k+'='+old[opt_k]+'\n'
path.write_text(''.join('VPNAAS_'+k+'='+v+'\n' for k,v in values.items())+'VPNAAS_DB=/var/lib/vpnaas/data.sqlite3\nVPNAAS_ROUTE_AUTO=1\nVPNAAS_USE_VICI=1\n'+extra_meta+('VPNAAS_POOL_CIDR='+old['VPNAAS_POOL_CIDR']+'\n' if old.get('VPNAAS_POOL_CIDR') else ''))
path.chmod(0o600)
key=Path('/etc/vpnaas/api.key')
if not key.exists():
    import secrets
    fd=os.open(key,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
    with os.fdopen(fd,'w') as f:f.write(secrets.token_hex(32)+'\n')
key.chmod(0o600)
if not lan and values['LAN_CIDR']=='192.0.2.0/24':print('No private LAN detected: safe placeholder 192.0.2.0/24. Set LAN_CIDR/LAN_IF/LAN_IP before LAN use.')
print('Gateway '+values['PUBLIC_IP']+' via '+values['PUBLIC_IF']+'; LAN '+values['LAN_CIDR']+' via '+values['LAN_IF'])
CONFIG
# Stop readers before replacing source: they must never observe new code with old env.
systemctl stop vpnaas-reconcile.timer vpnaas-reconcile.service vpnaas-api.service 2>/dev/null || true
# The archive contains only explicitly allowlisted source files.
base64 -d <<'VPNAAS_PAYLOAD' | tar -xz --no-same-owner -C /opt/vpnaas/backend
@@PAYLOAD@@
VPNAAS_PAYLOAD
systemctl enable --now strongswan.service
python3 /opt/vpnaas/backend/pool.py
python3 -m venv /opt/vpnaas/backend/venv
/opt/vpnaas/backend/venv/bin/pip install --disable-pip-version-check -r /opt/vpnaas/backend/requirements.txt
set -a
. /etc/vpnaas/backend.env
set +a
# Do not silently replace a partially missing PKI; require operator recovery.
if [[ ! -e /var/lib/vpnaas/ca-key.pem && ! -e /etc/swanctl/x509ca/ca.pem && ! -e /etc/swanctl/private/server-key.pem && ! -e /etc/swanctl/x509/server.pem ]]; then
    pki --gen --type rsa --size 3072 --outform pem > /var/lib/vpnaas/ca-key.pem
    pki --self --ca --lifetime 3650 --in /var/lib/vpnaas/ca-key.pem --type rsa --dn 'CN=VPNaaS CA' --outform pem > /etc/swanctl/x509ca/ca.pem
    pki --gen --type rsa --size 3072 --outform pem > /etc/swanctl/private/server-key.pem
    pki --pub --in /etc/swanctl/private/server-key.pem --type rsa | pki --issue --lifetime 825 --cacert /etc/swanctl/x509ca/ca.pem --cakey /var/lib/vpnaas/ca-key.pem --dn "CN=$VPNAAS_PUBLIC_IP" --san "$VPNAAS_PUBLIC_IP" --flag serverAuth --outform pem > /etc/swanctl/x509/server.pem
else
    for f in /var/lib/vpnaas/ca-key.pem /etc/swanctl/x509ca/ca.pem /etc/swanctl/private/server-key.pem /etc/swanctl/x509/server.pem; do
        [[ -s $f ]] || { echo "Incomplete PKI: $f. Restore backup before rerun." >&2; exit 1; }
    done
fi
openssl verify -CAfile /etc/swanctl/x509ca/ca.pem -verify_ip "$VPNAAS_PUBLIC_IP" /etc/swanctl/x509/server.pem
chmod 600 /var/lib/vpnaas/ca-key.pem /etc/swanctl/private/server-key.pem
cat > /opt/vpnaas/backend/run <<'RUN'
#!/usr/bin/env bash
set -euo pipefail
export VPNAAS_API_KEY="$(</etc/vpnaas/api.key)"
exec "$@"
RUN
chmod 700 /opt/vpnaas/backend/run
# Pin public NIC source routing & default route priority BEFORE sysctl/offload tuning so SSH never drops on multi-NIC VMs.
python3 -c "import sys; sys.path.insert(0,'/opt/vpnaas/backend'); import network; print('Public routing:', network.ensure_public_routing())" || true
python3 /opt/vpnaas/backend/tuning.py --configure
cat > /etc/systemd/system/vpnaas-api.service <<'UNIT'
[Unit]
Description=VPNaaS backend (loopback)
After=network-online.target strongswan.service
Wants=network-online.target
Requires=strongswan.service
[Service]
Type=simple
User=root
WorkingDirectory=/opt/vpnaas/backend
EnvironmentFile=/etc/vpnaas/backend.env
ExecStartPre=/opt/vpnaas/backend/run /opt/vpnaas/backend/venv/bin/python -c "from vpn import apply; apply()"
ExecStart=/opt/vpnaas/backend/run /opt/vpnaas/backend/venv/bin/uvicorn app:app --host 127.0.0.1 --port 8000 --no-access-log
Restart=always
RestartSec=3
LimitNOFILE=65536
UMask=0077
PrivateTmp=true
ProtectHome=true
NoNewPrivileges=true
StandardOutput=journal
StandardError=journal
[Install]
WantedBy=multi-user.target
UNIT
cat > /etc/systemd/system/vpnaas-reconcile.service <<'RECONCILE'
[Unit]
Description=Reconcile owned VPNaaS nftables with kernel routes
After=vpnaas-api.service
[Service]
Type=oneshot
WorkingDirectory=/opt/vpnaas/backend
EnvironmentFile=/etc/vpnaas/backend.env
ExecStart=/opt/vpnaas/backend/venv/bin/python -m network
UMask=0077
RECONCILE
cat > /etc/systemd/system/vpnaas-reconcile.timer <<'TIMER'
[Unit]
Description=Track late private NIC and route changes
[Timer]
OnBootSec=15
OnUnitActiveSec=5
AccuracySec=1
[Install]
WantedBy=timers.target
TIMER
cat > /etc/systemd/system/vpnaas-offload.service <<'OFFLOAD'
[Unit]
Description=VPNaaS public NIC offload readiness (does not change MTU)
After=network-online.target
[Service]
Type=oneshot
WorkingDirectory=/opt/vpnaas/backend
EnvironmentFile=-/etc/vpnaas/backend.env
ExecStart=/usr/bin/python3 /opt/vpnaas/backend/tuning.py
OFFLOAD
cat > /etc/systemd/system/vpnaas-offload.timer <<'OFFTIMER'
[Unit]
Description=Recheck offloads after NIC and public route changes
[Timer]
OnBootSec=20
OnUnitActiveSec=30
AccuracySec=2
[Install]
WantedBy=timers.target
OFFTIMER
install -d /etc/systemd/system/strongswan.service.d
printf '[Service]\nLimitNOFILE=65536\n' > /etc/systemd/system/strongswan.service.d/limits.conf
systemctl daemon-reload
systemctl enable --now vpnaas-offload.timer
systemctl enable --now vpnaas-reconcile.timer
systemctl enable --now strongswan.service
systemctl enable vpnaas-api.service
systemctl restart vpnaas-api.service
python3 - <<'READY'
from pathlib import Path
import urllib.request, time
for _ in range(90):
    try:
        r=urllib.request.urlopen(urllib.request.Request('http://127.0.0.1:8000/api/health',headers={'X-API-Key':Path('/etc/vpnaas/api.key').read_text().strip()}),timeout=2)
        assert r.status==200
        print('VPNaaS ready: http://127.0.0.1:8000; API key /etc/vpnaas/api.key (root-only)')
        break
    except Exception:time.sleep(1)
else:raise SystemExit('Backend not ready. Inspect journalctl -u vpnaas-api')
READY
