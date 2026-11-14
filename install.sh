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
NhKHlRd1uzLjf/6ldTVLXWti77TcjveEQlW5e+LZavObE5TW+OqEYbRfKj7+FfseLZvKloIGGFxY
gpMSLZXZnCyfdOsMbL3iKjp5T+IfcKfeb74Iz/yqz6+4EU9uKziorsmeG2zwt92hp52Nr73NUN2z
93Qwn44wkIhjXIu9DucVcCiqPemgut8buPIETI/ypsUkT8NeIXO5i7N50SgEGwF6CURWdfLU/LDd
UPe9rd2d1Fd/jNWHHPJzviDVUfdm+IrjrXM9kmyQDsy0L+t8xSRLk3wFfVTTf/E8Y/fXsBmlmTgw
wC3o/EDS5is8IAA2ht9iof6KUwfvibNMk3NqnyaBt/gG/qWNBbPE6SVk7LevLO0UtL5GYO1Zp/Bw
1npRhcjYxonmbv3G89zx0BySG1x3Hdl8IFUFpVMx85rAAAQldxdFHObXwsyPgLVsMOruBBH7rHsD
ryks9vVxI+TWIivp2koil9rADxsCW7eGxme0ZAV59bX8vkuNjgsyoFgM2lfQVBKQYfXdmtVT1AqG
rvKtPTY+rIqj8CSKawwov0KLnN69+kM+xCLjJMKbsOnwUWtaGB0tk/r6A6k+kBNmC+wWGp7KU92N
YQsuJokguxHfpHQtQe1ivgzfgf5LGYyz4efQJFeTZnXFyECYwytU1AUqFARfz/YvsDOCQA4Du41T
3j7bZ/tsn+2zfbbP9tk+22f7bJ/ts322z/bZPttn+2yf7bN9ts/22T7bZ/tsn+2zfbbP9tk+7c//
AdYq/KUAoAAA
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
