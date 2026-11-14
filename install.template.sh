#!/usr/bin/env bash
set -euo pipefail
# Edit these values, or pass environment variables. Empty = detect/preserve.
PUBLIC_IP="${PUBLIC_IP:-}"
PUBLIC_IF="${PUBLIC_IF:-}"
LAN_CIDR="${LAN_CIDR:-}"
LAN_IF="${LAN_IF:-}"
LAN_IP="${LAN_IP:-}"
FULL_DNS="${FULL_DNS:-}"
export PUBLIC_IP PUBLIC_IF LAN_CIDR LAN_IF LAN_IP FULL_DNS
[[ $EUID -eq 0 ]] || { echo 'Run as root' >&2; exit 1; }
. /etc/os-release
[[ $ID == debian && $VERSION_ID == 13 ]] || { echo 'Debian 13 required' >&2; exit 1; }
export DEBIAN_FRONTEND=noninteractive
umask 077
apt-get update
apt-get install -y --no-install-recommends ca-certificates curl openssl python3 python3-venv nftables iproute2 charon-systemd strongswan-swanctl strongswan-pki libcharon-extra-plugins libcharon-extauth-plugins libstrongswan-extra-plugins libstrongswan-standard-plugins
install -d -m 700 /opt/vpnaas/backend /var/lib/vpnaas /etc/vpnaas /etc/swanctl/conf.d /etc/swanctl/private /etc/swanctl/x509 /etc/swanctl/x509ca
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
path.write_text(''.join('VPNAAS_'+k+'='+v+'\n' for k,v in values.items())+'VPNAAS_DB=/var/lib/vpnaas/data.sqlite3\nVPNAAS_ROUTE_AUTO=1\n')
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
# The archive contains only the five allowlisted application source files.
base64 -d <<'VPNAAS_PAYLOAD' | tar -xz --no-same-owner -C /opt/vpnaas/backend
@@PAYLOAD@@
VPNAAS_PAYLOAD
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
printf 'net.ipv4.ip_forward=1\n' > /etc/sysctl.d/90-vpnaas.conf
sysctl -p /etc/sysctl.d/90-vpnaas.conf
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
systemctl daemon-reload
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
