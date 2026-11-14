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
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
4vn/iREJEgCgAAA=
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
