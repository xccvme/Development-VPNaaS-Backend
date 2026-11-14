#!/usr/bin/env bash
set -euo pipefail
# Edit these values, or pass environment variables. Empty = detect/preserve.
PUBLIC_IP="${PUBLIC_IP:-}"
PUBLIC_IF="${PUBLIC_IF:-}"
LAN_CIDR="${LAN_CIDR:-}"
LAN_IF="${LAN_IF:-}"
LAN_IP="${LAN_IP:-}"
FULL_DNS="${FULL_DNS:-}"
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
export PUBLIC_IP PUBLIC_IF LAN_CIDR LAN_IF LAN_IP FULL_DNS
[[ $EUID -eq 0 ]] || { echo 'Run as root' >&2; exit 1; }
. /etc/os-release
[[ $ID == debian && $VERSION_ID == 13 ]] || { echo 'Debian 13 required' >&2; exit 1; }
export DEBIAN_FRONTEND=noninteractive
umask 077
apt-get update
apt-get install -y --no-install-recommends ca-certificates curl openssl python3 python3-venv nftables iproute2 ethtool kmod charon-systemd strongswan-swanctl strongswan-pki libcharon-extra-plugins libcharon-extauth-plugins libstrongswan-extra-plugins libstrongswan-standard-plugins
install -d -m 700 /opt/vpnaas/backend /var/lib/vpnaas /etc/vpnaas /etc/swanctl/conf.d /etc/swanctl/private /etc/swanctl/x509 /etc/swanctl/x509ca
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
addresses=json.loads(subprocess.check_output(['ip','-j','-4','addr']))
private=[(a['ifname'],x) for a in addresses for x in a['addr_info'] if x.get('scope')=='global' and ipaddress.IPv4Address(x['local']).is_private and a['ifname']!=route['dev']]
lan=private[0] if private else None
fallback={'PUBLIC_IP':route.get('prefsrc') or route.get('src'),'PUBLIC_IF':route['dev'],'LAN_CIDR':str(ipaddress.IPv4Network(f"{lan[1]['local']}/{lan[1]['prefixlen']}",strict=False)) if lan else '192.0.2.0/24','LAN_IF':lan[0] if lan else route['dev'],'LAN_IP':lan[1]['local'] if lan else route.get('prefsrc') or route.get('src'),'FULL_DNS':'1.1.1.1,8.8.8.8'}
values={k:os.environ.get(k) or old.get('VPNAAS_'+k) or v for k,v in fallback.items()}
for k in ('PUBLIC_IP','LAN_IP'): values[k]=str(ipaddress.IPv4Address(values[k]))
if not ipaddress.IPv4Address(values['PUBLIC_IP']).is_global:raise SystemExit('PUBLIC_IP must be actual public IPv4; set PUBLIC_IP explicitly for NAT deployments')
values['LAN_CIDR']=str(ipaddress.IPv4Network(values['LAN_CIDR'],strict=False))
if values['LAN_CIDR']=='0.0.0.0/0':raise SystemExit('LAN_CIDR cannot be default route')
for k in ('PUBLIC_IF','LAN_IF'):
    if not re.fullmatch(r'[a-zA-Z0-9_.:-]{1,15}',values[k]) or not Path('/sys/class/net',values[k]).exists():raise SystemExit('Invalid interface '+k)
values['FULL_DNS']=','.join(str(ipaddress.IPv4Address(x.strip())) for x in values['FULL_DNS'].split(','))
if not 1<=len(values['FULL_DNS'].split(','))<=4:raise SystemExit('Set 1-4 DNS servers')
path.write_text(''.join('VPNAAS_'+k+'='+v+'\n' for k,v in values.items())+'VPNAAS_DB=/var/lib/vpnaas/data.sqlite3\nVPNAAS_ROUTE_AUTO=1\n'+('VPNAAS_POOL_CIDR='+old['VPNAAS_POOL_CIDR']+'\n' if old.get('VPNAAS_POOL_CIDR') else ''))
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
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
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
