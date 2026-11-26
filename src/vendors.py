"""Multi-vendor IPsec/IKEv2 S2S configuration generators.

Supports Linux strongSwan (swanctl + Debian/Ubuntu setup script), MikroTik
RouterOS v7, FortiGate FortiOS, and Cisco IOS-XE for both Multi-Site S2S
(`/api/sites`) and VPN Hub (`/api/connections` topology=hub).
"""
import ipaddress
import re
from store import ts_split

VENDORS = ('swanctl', 'script', 'mikrotik', 'fortigate', 'cisco')
MSS = 1300


def _clean_label(value, fallback='site'):
    return re.sub(r'[^A-Za-z0-9_.-]+', '-', str(value)).strip('-') or str(fallback)


def _slug_id(value, fallback='site'):
    return re.sub(r'[^A-Za-z0-9_-]+', '_', str(value)).strip('_') or str(fallback)


def _net_mask(cidr_str):
    net = ipaddress.IPv4Network(cidr_str)
    return str(net.network_address), str(net.netmask), str(net.hostmask)


def _hub_ip():
    from vpn import public_ip
    return public_ip()


def filename(label, vendor):
    clean = _clean_label(label)
    ext = {
        'swanctl': '.conf',
        'script': '.sh',
        'mikrotik': '.rsc',
        'fortigate': '.conf',
        'cisco': '.cfg',
    }[vendor]
    prefix = {
        'swanctl': 'Swanctl-',
        'script': 'Setup-',
        'mikrotik': 'MikroTik-',
        'fortigate': 'FortiGate-',
        'cisco': 'Cisco-IOSXE-',
    }[vendor]
    return f'{prefix}{clean}{ext}'


def render_swanctl(conn_name, child_name, site_label, local_id, local_subnets, remote_subnets,
                   auth_method='psk', psk='', encap=True, dpd_delay=30, ike_proposals='aes256-sha256-modp2048',
                   esp_proposals='aes256-sha256'):
    hub = _hub_ip()
    encap_line = '    encap = yes\n' if encap else ''
    if auth_method == 'pubkey':
        local_block = f'''    local {{
      auth = pubkey
      certs = {conn_name}.pem
      id = {local_id}
    }}'''
        remote_block = f'''    remote {{
      auth = pubkey
      id = {hub}
      cacerts = ca.pem
    }}'''
        secret_block = '# Gunakan sertifikat X.509 dari /api/pki/certs/{id}/bundle (taruh di /etc/swanctl/x509/ & private/)\n'
    else:
        local_block = f'''    local {{
      auth = psk
      id = {local_id}
    }}'''
        remote_block = f'''    remote {{
      auth = psk
      id = {hub}
    }}'''
        secret_block = f'''secrets {{
  ike-{conn_name} {{
    id-1 = {local_id}
    id-2 = {hub}
    secret = "{psk}"
  }}
}}
'''
    return f'''# VPNaaS IPsec/IKEv2 Site "{site_label}"
# Simpan sebagai /etc/swanctl/conf.d/{conn_name}.conf (mode 600), lalu: swanctl --load-all
# Subnet lokal (site ini): {local_subnets}
# Subnet remote (via VPNaaS Hub): {remote_subnets}
connections {{
  {conn_name} {{
    version = 2
    remote_addrs = {hub}
    proposals = {ike_proposals}
    dpd_delay = {dpd_delay}s
    keyingtries = 0
{encap_line}{local_block}
{remote_block}
    children {{
      {child_name} {{
        local_ts = {local_subnets}
        remote_ts = {remote_subnets}
        esp_proposals = {esp_proposals}
        start_action = start
        dpd_action = restart
        close_action = start
      }}
    }}
  }}
}}

{secret_block}'''


def render_script(site_id, conn_name, child_name, site_label, local_id, local_subnets, remote_subnets,
                  auth_method='psk', psk='', nat=True, encap=True, dpd_delay=30,
                  ike_proposals='aes256-sha256-modp2048', esp_proposals='aes256-sha256'):
    hub = _hub_ip()
    table = f'vpnaas_site_{site_id}'
    unit = f'vpnaas-site-{site_id}'
    local = ' '.join(ts_split(local_subnets))
    remote = ' '.join(ts_split(remote_subnets))
    conf = render_swanctl(
        conn_name, child_name, site_label, local_id, local_subnets, remote_subnets,
        auth_method=auth_method, psk=psk, encap=encap, dpd_delay=dpd_delay,
        ike_proposals=ike_proposals, esp_proposals=esp_proposals,
    )
    script_name = filename(site_label, 'script')
    return f'''#!/usr/bin/env bash
# VPNaaS Site "{site_label}" - setup Debian/Ubuntu (idempoten).
# Pemakaian:  sudo bash {script_name}
#             sudo bash {script_name} --uninstall
# RAHASIA: simpan mode 600 dan hapus setelah selesai.
set -euo pipefail
umask 077

NAME='{conn_name}'
CHILD='{child_name}'
CONF='/etc/swanctl/conf.d/{conn_name}.conf'
TABLE='{table}'
STATE_DIR='/etc/vpnaas-spoke'
NFT_FILE="$STATE_DIR/{conn_name}.nft"
UNIT='{unit}'
SYSCTL_FILE='/etc/sysctl.d/60-{conn_name}.conf'
HUB='{hub}'
LOCAL_NETS='{local}'
REMOTE_NETS='{remote}'
NAT={1 if nat else 0}
MSS={MSS}

log() {{ printf '[vpnaas-site] %s\\n' "$*"; }}
[ "$(id -u)" -eq 0 ] || {{ echo 'Jalankan sebagai root (sudo).' >&2; exit 1; }}

if [ "${{1:-}}" = '--uninstall' ]; then
  log "Menghapus $NAME"
  swanctl --terminate --ike "$NAME" --timeout 10 >/dev/null 2>&1 || true
  rm -f "$CONF"
  swanctl --load-conns >/dev/null 2>&1 || true
  nft delete table inet "$TABLE" >/dev/null 2>&1 || true
  systemctl disable --now "$UNIT.service" >/dev/null 2>&1 || true
  rm -f "/etc/systemd/system/$UNIT.service" "$NFT_FILE" "$SYSCTL_FILE"
  systemctl daemon-reload || true
  rmdir "$STATE_DIR" 2>/dev/null || true
  exit 0
fi
[ $# -eq 0 ] || {{ echo "Argumen tidak dikenal: $1 (gunakan --uninstall)" >&2; exit 2; }}

missing=()
for pkg in strongswan-swanctl charon-systemd libstrongswan-standard-plugins nftables; do
  [ "$(dpkg-query -W -f='${{Status}}' "$pkg" 2>/dev/null || true)" = 'install ok installed' ] || missing+=("$pkg")
done
if [ "${{#missing[@]}}" -gt 0 ]; then
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -q
  apt-get install -y -q --no-install-recommends "${{missing[@]}}"
fi
systemctl is-active --quiet strongswan || systemctl enable --now strongswan

mkdir -p /etc/swanctl/conf.d "$STATE_DIR"
tmp=$(mktemp /etc/swanctl/conf.d/.vpnaas-site.XXXXXX)
cat > "$tmp" <<'VPNAAS_SWANCTL_EOF'
{conf}VPNAAS_SWANCTL_EOF
chmod 600 "$tmp"
changed=1
if [ -f "$CONF" ] && cmp -s "$tmp" "$CONF"; then changed=0; fi
mv -f "$tmp" "$CONF"

printf 'net.ipv4.ip_forward = 1\\n' > "$SYSCTL_FILE"
chmod 644 "$SYSCTL_FILE"
sysctl -q -w net.ipv4.ip_forward=1

L="{{ ${{LOCAL_NETS// /, }} }}"
R="{{ ${{REMOTE_NETS// /, }} }}"
nat_rules=''
if [ "$NAT" = 1 ]; then
  for net in $LOCAL_NETS; do
    probe="${{net%/*}}"
    dev=$(ip -4 -o route get "$probe" 2>/dev/null | sed -n 's/.* dev \\([^ ]*\\).*/\\1/p' || true)
    if [ -n "$dev" ]; then
      nat_rules+="    ip saddr $R ip daddr $net oifname \\"$dev\\" masquerade"$'\\n'
    fi
  done
fi
cat > "$NFT_FILE" <<VPNAAS_NFT_EOF
table inet $TABLE
delete table inet $TABLE
table inet $TABLE {{
  chain forward {{
    type filter hook forward priority filter; policy accept;
    ip saddr $R ip daddr $L meta ipsec exists accept
    ip saddr $L ip daddr $R rt ipsec exists accept
  }}
  chain mss {{
    type filter hook forward priority mangle; policy accept;
    ip saddr $R ip daddr $L meta ipsec exists tcp flags & (syn|rst) == syn tcp option maxseg size > $MSS tcp option maxseg size set $MSS
    ip saddr $L ip daddr $R rt ipsec exists tcp flags & (syn|rst) == syn tcp option maxseg size > $MSS tcp option maxseg size set $MSS
  }}
  chain postrouting {{
    type nat hook postrouting priority srcnat; policy accept;
$nat_rules  }}
}}
VPNAAS_NFT_EOF
chmod 600 "$NFT_FILE"
nft --check -f "$NFT_FILE"
nft -f "$NFT_FILE"

cat > "/etc/systemd/system/$UNIT.service" <<VPNAAS_UNIT_EOF
[Unit]
Description=VPNaaS site firewall $NAME
After=network-pre.target nftables.service
[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/sbin/nft -f $NFT_FILE
ExecStop=-/usr/sbin/nft delete table inet $TABLE
[Install]
WantedBy=multi-user.target
VPNAAS_UNIT_EOF
systemctl daemon-reload
systemctl enable "$UNIT.service" >/dev/null 2>&1 || true

swanctl --load-all
up() {{ local sas; sas=$(swanctl --list-sas --ike "$NAME" 2>/dev/null || true); grep -q "$CHILD.*INSTALLED" <<<"$sas"; }}
if [ "$changed" = 1 ] && up; then
  swanctl --terminate --ike "$NAME" --timeout 10 >/dev/null 2>&1 || true
fi
for _ in 1 2 3 4 5 6; do up && break; sleep 2; done
if ! up; then
  swanctl --initiate --child "$CHILD" --timeout 30 >/dev/null 2>&1 || true
fi
swanctl --list-sas --ike "$NAME" 2>/dev/null || true
if up; then log "AKTIF: $LOCAL_NETS <-> $REMOTE_NETS via hub $HUB"; else log 'BELUM AKTIF'; exit 3; fi
'''


def render_mikrotik(site_label, local_id, local_subnets, remote_subnets,
                    auth_method='psk', psk='', dpd_delay=30):
    """MikroTik RouterOS v7 IPsec/IKEv2 configuration script."""
    hub = _hub_ip()
    name = 'vpnaas-' + _slug_id(site_label)
    locals_ = ts_split(local_subnets)
    remotes_ = ts_split(remote_subnets)

    if auth_method == 'pubkey':
        identity_line = (
            f'/ip ipsec identity add peer="{name}" auth-method=digital-signature '
            f'certificate="{name}-cert" remote-certificate=none '
            f'my-id="fqdn:{local_id}" remote-id="address:{hub}" generate-policy=no'
        )
    else:
        identity_line = (
            f'/ip ipsec identity add peer="{name}" auth-method=pre-shared-key '
            f'secret="{psk}" my-id="user-fqdn:{local_id}" remote-id="address:{hub}" '
            f'generate-policy=no'
        )

    lines = [
        f'# VPNaaS MikroTik RouterOS v7 - Site "{site_label}"',
        f'# Hub Gateway: {hub} | Local: {local_subnets} | Remote: {remote_subnets}',
        f'# RAHASIA: jaga file ini privat (berisi kredensial IPsec).',
        '',
        f'/ip ipsec profile add name="{name}-prof" hash-algorithm=sha256 enc-algorithm=aes-256 dh-group=modp2048 dpd-interval={dpd_delay}s dpd-maximum-failures=5 nat-traversal=yes',
        f'/ip ipsec proposal add name="{name}-prop" auth-algorithms=sha256 enc-algorithms=aes-256-cbc pfs-group=none',
        f'/ip ipsec peer add name="{name}" address={hub}/32 profile="{name}-prof" exchange-mode=ike2 send-initial-contact=yes',
        identity_line,
        '',
        '# Traffic Selector Policies (setiap pasangan subnet lokal <-> remote)',
    ]
    for l_sub in locals_:
        for r_sub in remotes_:
            lines.append(
                f'/ip ipsec policy add peer="{name}" tunnel=yes src-address={l_sub} dst-address={r_sub} '
                f'proposal="{name}-prop" action=encrypt level=unique'
            )
    lines += [
        '',
        '# Bypass SRC-NAT/Masquerade agar trafik IPsec tidak terkena NAT internet',
    ]
    for l_sub in locals_:
        for r_sub in remotes_:
            lines.append(
                f'/ip firewall nat add chain=srcnat place-before=0 src-address={l_sub} dst-address={r_sub} '
                f'action=accept comment="{name}-bypass"'
            )
    lines += [
        '',
        '# Clamp MSS TCP ke 1300 untuk mencegah fragmentasi IPsec',
    ]
    for l_sub in locals_:
        for r_sub in remotes_:
            lines.append(
                f'/ip firewall mangle add chain=forward src-address={l_sub} dst-address={r_sub} '
                f'protocol=tcp tcp-flags=syn tcp-mss=1301-65535 action=change-mss new-mss={MSS} comment="{name}-mss"'
            )
    return '\n'.join(lines) + '\n'


def render_fortigate(site_label, local_id, local_subnets, remote_subnets,
                     auth_method='psk', psk='', dpd_delay=30):
    """FortiGate FortiOS CLI configuration (IKEv2 route-based phase1/phase2)."""
    hub = _hub_ip()
    name = ('vpn_' + _slug_id(site_label))[:15]
    locals_ = ts_split(local_subnets)
    remotes_ = ts_split(remote_subnets)

    if auth_method == 'pubkey':
        auth_lines = [
            '        set authmethod signature',
            f'        set certificate "{name}_cert"',
            '        set peer "VPNaaS_CA_Peer"',
        ]
    else:
        auth_lines = [
            '        set authmethod psk',
            f'        set psksecret "{psk}"',
        ]

    lines = [
        f'# VPNaaS FortiGate FortiOS CLI - Site "{site_label}"',
        f'# Sesuaikan "interface" (mis. wan1) dan "lan_intf" (mis. internal/port2) sesuai perangkat Anda.',
        'config vpn ipsec phase1-interface',
        f'    edit "{name}"',
        '        set interface "wan1"',
        '        set ike-version 2',
        '        set keylife 28800',
        '        set peertype any',
        '        set net-device disable',
        '        set proposal aes256-sha256 aes128-sha256',
        '        set dhgrp 14',
        '        set nattraversal forced',
        f'        set dpd on-idle',
        f'        set dpd-retryinterval {dpd_delay}',
        f'        set localid "{local_id}"',
        f'        set remote-gw {hub}',
        *auth_lines,
        '    next',
        'end',
        '',
        'config vpn ipsec phase2-interface',
    ]
    idx = 1
    for l_sub in locals_:
        l_ip, l_mask, _ = _net_mask(l_sub)
        for r_sub in remotes_:
            r_ip, r_mask, _ = _net_mask(r_sub)
            lines += [
                f'    edit "{name}_p2_{idx}"',
                f'        set phase1name "{name}"',
                '        set proposal aes256-sha256 aes128-sha256',
                '        set pfs disable',
                '        set auto-negotiate enable',
                f'        set src-subnet {l_ip} {l_mask}',
                f'        set dst-subnet {r_ip} {r_mask}',
                '    next',
            ]
            idx += 1
    lines += [
        'end',
        '',
        'config router static',
    ]
    for r_sub in remotes_:
        r_ip, r_mask, _ = _net_mask(r_sub)
        lines += [
            '    edit 0',
            f'        set dst {r_ip} {r_mask}',
            f'        set device "{name}"',
            '    next',
        ]
    lines += [
        'end',
        '',
        f'# Pastikan firewall policy mengizinkan LAN <-> "{name}" dengan tcp-mss-sender {MSS} / tcp-mss-receiver {MSS}.',
    ]
    return '\n'.join(lines) + '\n'


def render_cisco(site_label, local_id, local_subnets, remote_subnets,
                 auth_method='psk', psk='', dpd_delay=30):
    """Cisco IOS-XE IKEv2 IPsec configuration."""
    hub = _hub_ip()
    name = _slug_id(site_label).upper()
    locals_ = ts_split(local_subnets)
    remotes_ = ts_split(remote_subnets)

    lines = [
        f'! VPNaaS Cisco IOS-XE IKEv2 - Site "{site_label}"',
        f'! Hub Gateway: {hub} | Local: {local_subnets} | Remote: {remote_subnets}',
        '!',
        f'crypto ikev2 proposal VPNAAS-PROP-{name}',
        ' encryption aes-cbc-256 aes-cbc-128',
        ' integrity sha256',
        ' group 14',
        '!',
        f'crypto ikev2 policy VPNAAS-POL-{name}',
        f' proposal VPNAAS-PROP-{name}',
        '!',
    ]
    if auth_method == 'psk':
        lines += [
            f'crypto ikev2 keyring VPNAAS-KR-{name}',
            f' peer VPNAAS-HUB-{name}',
            f'  address {hub}',
            f'  pre-shared-key {psk}',
            '!',
        ]
    lines += [
        f'crypto ikev2 profile VPNAAS-PROF-{name}',
        f' match identity remote address {hub} 255.255.255.255',
        f' identity local {"email" if "@" in local_id else "fqdn"} {local_id}',
    ]
    if auth_method == 'pubkey':
        lines += [
            ' authentication remote rsa-sig',
            ' authentication local rsa-sig',
            f' pki trustpoint VPNAAS-TP-{name}',
        ]
    else:
        lines += [
            ' authentication remote pre-share',
            ' authentication local pre-share',
            f' keyring local VPNAAS-KR-{name}',
        ]
    lines += [
        f' dpd {dpd_delay} 5 periodic',
        ' nat keepalive 20',
        '!',
        f'crypto ipsec transform-set VPNAAS-TS-{name} esp-aes 256 esp-sha256-hmac',
        ' mode tunnel',
        '!',
        f'ip access-list extended VPNAAS-ACL-{name}',
    ]
    for l_sub in locals_:
        l_ip, _, l_wild = _net_mask(l_sub)
        for r_sub in remotes_:
            r_ip, _, r_wild = _net_mask(r_sub)
            lines.append(f' permit ip {l_ip} {l_wild} {r_ip} {r_wild}')
    lines += [
        '!',
        f'crypto map VPNAAS-MAP 10 ipsec-isakmp',
        f' set peer {hub}',
        f' set transform-set VPNAAS-TS-{name}',
        f' set ikev2-profile VPNAAS-PROF-{name}',
        f' match address VPNAAS-ACL-{name}',
        '!',
        f'! Terapkan "crypto map VPNAAS-MAP" pada interface WAN dan "ip tcp adjust-mss {MSS}" pada interface LAN.',
    ]
    return '\n'.join(lines) + '\n'


def generate_for_site(site, local_ts_on_hub, vendor='swanctl', routes=None):
    """Generate vendor configuration for a Multi-Site S2S resource."""
    from store import site_effective_subnets
    conn_name = f"vpnaas-site-{site['id']}"
    child_name = f"vpnaas-site-{site['id']}-net"
    # On the spoke/peer router, its local_ts is site's subnets (+ site_id routes) and its remote_ts is hub's local_ts!
    local_subnets = ','.join(site_effective_subnets(site, routes=routes)) if routes is not None else site['subnets']
    remote_subnets = local_ts_on_hub
    auth = site.get('auth_method', 'psk')
    psk = site.get('psk', '')
    dpd = site.get('dpd_delay', 30)
    if vendor == 'swanctl':
        text = render_swanctl(
            conn_name, child_name, site['name'], site['ike_id'],
            local_subnets, remote_subnets, auth_method=auth, psk=psk,
            encap=site.get('encap', True), dpd_delay=dpd,
            ike_proposals=site.get('ike_proposals', 'aes256-sha256-modp2048'),
            esp_proposals=site.get('esp_proposals', 'aes256-sha256'),
        )
    elif vendor == 'script':
        text = render_script(
            site['id'], conn_name, child_name, site['name'], site['ike_id'],
            local_subnets, remote_subnets, auth_method=auth, psk=psk,
            nat=site.get('nat', True), encap=site.get('encap', True), dpd_delay=dpd,
            ike_proposals=site.get('ike_proposals', 'aes256-sha256-modp2048'),
            esp_proposals=site.get('esp_proposals', 'aes256-sha256'),
        )
    elif vendor == 'mikrotik':
        text = render_mikrotik(site['name'], site['ike_id'], local_subnets, remote_subnets, auth_method=auth, psk=psk, dpd_delay=dpd)
    elif vendor == 'fortigate':
        text = render_fortigate(site['name'], site['ike_id'], local_subnets, remote_subnets, auth_method=auth, psk=psk, dpd_delay=dpd)
    elif vendor == 'cisco':
        text = render_cisco(site['name'], site['ike_id'], local_subnets, remote_subnets, auth_method=auth, psk=psk, dpd_delay=dpd)
    else:
        raise ValueError(f'Unsupported vendor: {vendor}')
    return text, filename(site['name'], vendor)


def generate_for_hub(connection, side, vendor='swanctl'):
    """Generate vendor configuration for one side ('a'/'b') of a VPN Hub connection."""
    import spoke
    if vendor == 'swanctl':
        return spoke.swanctl(connection, side), spoke.filename(connection, side, 'swanctl')
    if vendor == 'script':
        return spoke.script(connection, side), spoke.filename(connection, side, 'script')
    me = connection['site_' + side]
    peer = connection['site_' + spoke.other(side)]
    label = f"{connection['name']}-Site-{side.upper()}"
    if vendor == 'mikrotik':
        text = render_mikrotik(label, me['id'], me['subnets'], peer['subnets'], auth_method='psk', psk=me['psk'])
    elif vendor == 'fortigate':
        text = render_fortigate(label, me['id'], me['subnets'], peer['subnets'], auth_method='psk', psk=me['psk'])
    elif vendor == 'cisco':
        text = render_cisco(label, me['id'], me['subnets'], peer['subnets'], auth_method='psk', psk=me['psk'])
    else:
        raise ValueError(f'Unsupported vendor: {vendor}')
    return text, filename(label, vendor)
