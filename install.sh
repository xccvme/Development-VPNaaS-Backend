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
p8/T5+nz9Hn6PH2ePk+f/6af/wfsCrBvAPAAAA==
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
