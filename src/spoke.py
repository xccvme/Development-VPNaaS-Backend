"""Spoke (site) configuration for VPN Hub connections.

Only validated database fields are interpolated: subnets are normalized CIDRs,
ids/names match store.safe(), PSK matches store.HUB_PSK (no quotes, $, `, \\ or
spaces), so the values are safe inside double-quoted swanctl strings and
single-quoted shell assignments.
"""
import re

MSS = 1300


def hub_address():
    from vpn import public_ip
    return public_ip()


def names(c, side):
    i = c['id']
    return f'vpnaas-hub-{i}-{side}', f'vpnaas-hub-{i}-{side}-net'


def other(side):
    return 'b' if side == 'a' else 'a'


def filename(c, side, kind):
    label = re.sub(r'[^A-Za-z0-9_.-]+', '-', c['name']).strip('-') or str(c['id'])
    site = 'Site-' + side.upper()
    return f'Setup-Hub-{label}-{site}.sh' if kind == 'script' else f'Hub-{label}-{site}.conf'


def swanctl(c, side):
    conn, child = names(c, side)
    me, peer = c['site_' + side], c['site_' + other(side)]
    hub = hub_address()
    return f'''# VPNaaS VPN Hub "{c['name']}" - {me['name']} (site {side.upper()})
# Simpan sebagai /etc/swanctl/conf.d/{conn}.conf (mode 600), lalu: swanctl --load-all
# Subnet lokal (site ini): {me['subnets']}
# Subnet site lawan via hub: {peer['subnets']}
connections {{
  {conn} {{
    version = 2
    remote_addrs = {hub}
    proposals = aes256-sha256-modp2048
    dpd_delay = 30s
    keyingtries = 0
    # ESP dibungkus UDP 4500 walau tanpa NAT: banyak security group cloud hanya membuka UDP 500/4500, bukan protokol ESP (50).
    encap = yes
    local {{
      auth = psk
      id = {me['id']}
    }}
    remote {{
      auth = psk
      id = {hub}
    }}
    children {{
      {child} {{
        local_ts = {me['subnets']}
        remote_ts = {peer['subnets']}
        esp_proposals = aes256-sha256
        start_action = start
        dpd_action = restart
        close_action = start
      }}
    }}
  }}
}}

secrets {{
  ike-{conn} {{
    id-1 = {me['id']}
    id-2 = {hub}
    secret = "{me['psk']}"
  }}
}}
'''


def script(c, side):
    conn, child = names(c, side)
    me, peer = c['site_' + side], c['site_' + other(side)]
    i = c['id']
    table = f'vpnaas_spoke_{i}'
    unit = f'vpnaas-spoke-{i}-{side}'
    local = ' '.join(me['subnets'].split(','))
    remote = ' '.join(peer['subnets'].split(','))
    conf = swanctl(c, side)
    return f'''#!/usr/bin/env bash
# VPNaaS VPN Hub "{c['name']}" - setup {me['name']} (site {side.upper()}) untuk Debian/Ubuntu.
# Pemakaian:  sudo bash {filename(c, side, 'script')}            # pasang / perbarui (idempoten)
#             sudo bash {filename(c, side, 'script')} --uninstall # hapus file & tabel milik script ini
# Script ini hanya menulis file miliknya sendiri dan tabel nft "inet {table}";
# konfigurasi strongSwan/nftables lain tidak dihapus atau di-flush.
# RAHASIA: file ini berisi PSK. Simpan mode 600 dan hapus setelah dipakai.
set -euo pipefail
umask 077

NAME='{conn}'
CHILD='{child}'
CONF='/etc/swanctl/conf.d/{conn}.conf'
TABLE='{table}'
STATE_DIR='/etc/vpnaas-spoke'
NFT_FILE="$STATE_DIR/{conn}.nft"
UNIT='{unit}'
SYSCTL_FILE='/etc/sysctl.d/60-{conn}.conf'
HUB='{hub_address()}'
LOCAL_NETS='{local}'
REMOTE_NETS='{remote}'
NAT={1 if me['nat'] else 0}
MSS={MSS}

log() {{ printf '[vpnaas-spoke] %s\\n' "$*"; }}
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
  log 'Selesai. net.ipv4.ip_forward tidak diubah (mungkin dipakai layanan lain).'
  exit 0
fi
[ $# -eq 0 ] || {{ echo "Argumen tidak dikenal: $1 (gunakan --uninstall)" >&2; exit 2; }}

# 1. Paket strongSwan (swanctl + charon-systemd) dan nftables bila belum ada.
missing=()
for pkg in strongswan-swanctl charon-systemd libstrongswan-standard-plugins nftables; do
  [ "$(dpkg-query -W -f='${{Status}}' "$pkg" 2>/dev/null || true)" = 'install ok installed' ] || missing+=("$pkg")
done
if [ "${{#missing[@]}}" -gt 0 ]; then
  log "Memasang paket: ${{missing[*]}}"
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -q
  apt-get install -y -q --no-install-recommends "${{missing[@]}}"
fi
if systemctl list-unit-files strongswan-starter.service >/dev/null 2>&1 && systemctl is-active --quiet strongswan-starter; then
  echo 'strongswan-starter (ipsec.conf) aktif; script ini butuh charon-systemd/swanctl.' >&2; exit 1
fi
systemctl is-active --quiet strongswan || systemctl enable --now strongswan
grep -qs 'conf.d/\\*.conf' /etc/swanctl/swanctl.conf || log 'PERINGATAN: /etc/swanctl/swanctl.conf tidak meng-include conf.d/*.conf'

# 2. Konfigurasi IPsec (mode 600).
mkdir -p /etc/swanctl/conf.d "$STATE_DIR"
tmp=$(mktemp /etc/swanctl/conf.d/.vpnaas-hub.XXXXXX)
cat > "$tmp" <<'VPNAAS_SWANCTL_EOF'
{conf}VPNAAS_SWANCTL_EOF
chmod 600 "$tmp"
changed=1
if [ -f "$CONF" ] && cmp -s "$tmp" "$CONF"; then changed=0; fi
mv -f "$tmp" "$CONF"
if [ "$changed" = 1 ]; then log "Menulis $CONF"; else log "$CONF tidak berubah"; fi

# 3. IP forwarding.
printf 'net.ipv4.ip_forward = 1\\n' > "$SYSCTL_FILE"
chmod 644 "$SYSCTL_FILE"
sysctl -q -w net.ipv4.ip_forward=1

# 4. Tabel nftables milik script (forward tunnel<->LAN, MSS clamp, NAT opsional).
L="{{ ${{LOCAL_NETS// /, }} }}"
R="{{ ${{REMOTE_NETS// /, }} }}"
nat_rules=''
if [ "$NAT" = 1 ]; then
  for net in $LOCAL_NETS; do
    probe="${{net%/*}}"
    dev=$(ip -4 -o route get "$probe" 2>/dev/null | sed -n 's/.* dev \\([^ ]*\\).*/\\1/p' || true)
    if [ -z "$dev" ]; then log "PERINGATAN: tidak ada route ke $net; NAT untuk subnet ini dilewati"; continue; fi
    nat_rules+="    ip saddr $R ip daddr $net oifname \\"$dev\\" masquerade"$'\\n'
    log "NAT: $REMOTE_NETS -> $net keluar via $dev (masquerade ke IP $dev)"
  done
fi
# File berisi batch lengkap (buat-hapus-buat) sehingga "nft -f" selalu idempoten dan atomik.
cat > "$NFT_FILE" <<VPNAAS_NFT_EOF
table inet $TABLE
delete table inet $TABLE
table inet $TABLE {{
  chain forward {{
    type filter hook forward priority filter; policy accept;
    ip saddr $R ip daddr $L meta ipsec exists accept
    ip saddr $L ip daddr $R accept
  }}
  chain mss {{
    type filter hook forward priority mangle; policy accept;
    ip saddr $R ip daddr $L meta ipsec exists tcp flags & (syn|rst) == syn tcp option maxseg size > $MSS tcp option maxseg size set $MSS
    ip saddr $L ip daddr $R tcp flags & (syn|rst) == syn tcp option maxseg size > $MSS tcp option maxseg size set $MSS
  }}
  chain postrouting {{
    type nat hook postrouting priority srcnat; policy accept;
$nat_rules  }}
}}
VPNAAS_NFT_EOF
chmod 600 "$NFT_FILE"
nft --check -f "$NFT_FILE"
nft -f "$NFT_FILE"
log "Tabel nft inet $TABLE diterapkan"
# Peringatan: tabel lain dengan forward policy drop tetap bisa membuang trafik.
if nft list ruleset 2>/dev/null | awk -v t="$TABLE" '/^table/{{cur=$3}} /hook forward/ && /policy drop/ && cur!=t {{f=1}} END{{exit !f}}'; then
  log "PERINGATAN: ada chain forward lain dengan 'policy drop'. Izinkan $REMOTE_NETS <-> $LOCAL_NETS di firewall itu."
fi

cat > "/etc/systemd/system/$UNIT.service" <<VPNAAS_UNIT_EOF
[Unit]
Description=VPNaaS hub spoke firewall $NAME
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

# 5. Muat konfigurasi (tanpa opsi clear: koneksi lain tetap) dan connect bila belum aktif.
if ! out=$(swanctl --load-all 2>&1); then printf '%s\n' "$out" | grep -v plugin >&2; exit 1; fi
# Tangkap output dulu: grep -q pada pipe + pipefail bisa gagal karena SIGPIPE.
up() {{ local sas; sas=$(swanctl --list-sas --ike "$NAME" 2>/dev/null || true); grep -q "$CHILD.*INSTALLED" <<<"$sas"; }}
if [ "$changed" = 1 ] && up; then
  # Parameter berubah: bangun ulang SA milik koneksi ini saja (SA lain tidak disentuh).
  log "Konfigurasi berubah: reconnect $NAME"
  swanctl --terminate --ike "$NAME" --timeout 10 >/dev/null 2>&1 || true
fi
for _ in 1 2 3 4 5 6; do up && break; sleep 2; done
if ! up; then
  log "Connect $CHILD ke hub $HUB"
  swanctl --initiate --child "$CHILD" --timeout 30 >/dev/null 2>&1 || true
fi
swanctl --list-sas --ike "$NAME" 2>/dev/null || true
if up; then log "AKTIF: $LOCAL_NETS <-> $REMOTE_NETS via hub $HUB"; else log 'BELUM AKTIF: periksa journalctl -u strongswan dan UDP 500/4500 ke hub'; exit 3; fi
'''
