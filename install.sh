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
