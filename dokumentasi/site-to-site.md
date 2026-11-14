# VPN Hub dan site-to-site (LAN ke LAN)

## VPN Hub: Site A ↔ hub publik ↔ Site B

Model `topology:hub` membentuk dua tunnel IKEv2 PSK terpisah. Hub meneruskan trafik A↔B; LAN hub tidak otomatis menjadi salah satu site. Model direct di bagian bawah tetap didukung tanpa menghapus koneksi/akun lama. Kontrak lengkap ada di [REST API](rest-api.md#4-connections-s2s-psk).

Isi nama hub, `site_a.subnets` dan `site_b.subnets` (masing-masing 1–8 CIDR IPv4 koma, tanpa /0, tidak overlap antar site atau pool VIP). Set alamat `%any` untuk site dinamis/NAT; IPv4/hostname untuk site yang dapat menerima IKE. ID dan PSK unik per site dibuat otomatis bila tidak diisi. `nat:true` default adalah masquerade LAN, bukan pengaturan NAT-T.

### Configure pada masing-masing site

Unduh Configure Site A/B melalui UI atau `GET /api/connections/{id}/sites/a/config?format=script` (B serupa). File mengandung PSK: transfer melalui SSH, mode 600, jangan dicetak/log/commit. Jalankan **di spoke yang tepat**, bukan kedua file pada hub.

```bash
chmod 600 Setup-Hub-kantor-Site-A.sh
bash -n Setup-Hub-kantor-Site-A.sh
sudo bash Setup-Hub-kantor-Site-A.sh
# Di site B jalankan file Site-B.
# Hapus hanya instalasi spoke ini bila diperlukan:
# sudo bash Setup-Hub-kantor-Site-A.sh --uninstall
```

Script Debian/Ubuntu root memasang paket yang belum tersedia, mengaktifkan forwarding IPv4, menulis konfigurasi mode600 `/etc/swanctl/conf.d/vpnaas-hub-<id>-a.conf`, tabel `inet vpnaas_spoke_<id>`, serta unit firewall `vpnaas-spoke-<id>-a.service` (B serupa). Konfigurasi/tabel lain tidak di-flush. Re-run idempoten; perubahan konfigurasi reconnect SA sendiri saja. Uninstall menghapus file/unit/tabel sendiri dan tidak mematikan forwarding global. Starter ipsec.conf aktif ditolak; gunakan charon-systemd/swanctl dan pastikan include conf.d/*.conf tersedia. Dua spoke hub yang sama harus berada pada mesin berbeda karena tabel nft memakai ID hub saja.

Setelah mengubah subnet/ID/PSK/NAT, unduh ulang dan jalankan Configure terbaru pada spoke terkait; hub tidak mengubah mesin spoke secara remote. NAT script mengikuti route/interface saat dijalankan, bukan reconciler dinamis: ulangi bila jalur/interface LAN berubah. `format=swanctl` hanya mengekspor konfigurasi IPsec, bukan forwarding/firewall/NAT.

### NAT tidak menggantikan route outbound

Dengan NAT aktif di A, trafik dari B ke host LAN A dimasquerade ke IP interface LAN spoke A. Host tujuan dapat membalas tanpa route khusus ke subnet B, tetapi log/ACL tujuan melihat **IP spoke A, bukan IP asli host B**. Hal sebaliknya berlaku untuk NAT di B.

**Host LAN yang memulai koneksi tetap memerlukan route ke subnet lawan via IP LAN spoke**, baik melalui default gateway spoke, static route di router LAN (disarankan), maupun route per host. Contoh A: `ip route add 10.2.0.0/24 via 10.1.0.1`; B: `ip route add 10.1.0.0/24 via 10.2.0.1`. Tanpa NAT, route dua arah juga diperlukan untuk balasan dan sumber asli dipertahankan. Spoke harus benar-benar dapat merutekan semua subnet lokalnya.

### Firewall, status dan auto-reconnect

Hub harus menerima UDP500/4500. Configure memakai `encap=yes` (ESP selalu UDP4500, terlihat TUNNEL-in-UDP), IKE AES256/SHA256/MODP2048 dan ESP AES256/SHA256; tidak perlu melemahkan crypto. Spoke NAT memulai koneksi. Connect hub ke `%any` ditolak 409; IP NAT statis pun tidak bisa diinisiasi dari hub tanpa port forwarding.

Spoke memakai `start_action=start`, `dpd_action=restart`, `close_action=start` dan retry tanpa batas. **Disconnect sementara** bisa langsung disusul reconnect otomatis. Untuk disable administratif ubah `enabled:false` di hub dan hentikan konfigurasi spoke bila diperlukan. GET list/detail mengembalikan nested site status active/down, remote_host, bytes_in/out. Active memerlukan ESTABLISHED + INSTALLED, bukan bukti LAN. Telemetry gagal saat ini juga menghasilkan down, sehingga cek journal. Legacy direct tidak memiliki nested runtime site.

Hub membuka transit A↔B dan clamp MSS maksimal1300; spoke punya tabel sendiri dan NAT opsional. **Accept di satu tabel nft tidak mengalahkan drop di tabel lain.** Backend lama/firewall lain pada spoke dengan policy drop harus diberi izin semua pasangan subnet dua arah lewat pemilik firewall itu. Script hanya memperingatkan, tidak mengubah firewall asing; jangan flush ruleset. OpenStack tanpa NAT memerlukan allowed-address-pairs subnet lawan pada port LAN dan security group sesuai. NAT ke IP NIC setempat membantu return path, bukan route outbound host.

Verifikasi kedua leg dengan `swanctl --list-sas`, counter sebelum/sesudah, ping dan TCP kedua arah. Ping bersumber IP LAN **dari gateway** membuktikan tunnel dan akses host tujuan, bukan bahwa host LAN arbitrer sudah memiliki route outbound. Bukti LAN-host penuh perlu host nyata atau netns+veth di belakang masing-masing spoke dengan route via spoke; jangan mengubah tunnel produksi hanya untuk simulasi. Tidak ada bukti uji deployment spesifik yang disimpan dalam Git.

## Legacy direct: gateway backend ini ↔ peer


Koneksi site-to-site (S2S) menghubungkan dua jaringan kantor/data center lewat tunnel IPsec IKEv2 dengan PSK. Host di LAN site A bisa berbicara langsung dengan host di LAN site B memakai IP privat masing-masing, tanpa klien VPN di host tersebut. Gateway VPNaaS hanya meneruskan paket; host LAN tetap harus tahu bahwa subnet seberang dicapai lewat gateway.

Kontrak API ada di [REST API bagian Connections](rest-api.md#4-connections-s2s-psk).

## Arti subnet lokal dan remote

| Field | Arti |
|---|---|
| `local_ts` | Subnet di belakang **gateway ini** yang boleh diakses dari seberang. |
| `remote_ts` | Subnet di belakang **peer** yang boleh diakses dari sini. |

Keduanya berupa string berisi 1–8 CIDR IPv4 dipisah koma, misalnya `10.1.0.0/24,10.1.10.0/24`. Backend menormalkan CIDR, membuang duplikat, dan menyimpan hasilnya sebagai `a,b`. Ditolak (HTTP 422): daftar kosong, lebih dari 8, `/0`, subnet lokal yang overlap dengan subnet remote, dan subnet yang overlap dengan pool VIP C2S server (`GET /api/status` → `pool_cidr`).

Kedua sisi **harus mencerminkan** satu sama lain: `local_ts` di site A sama dengan `remote_ts` di site B, dan sebaliknya. Jika daftar tidak cocok, strongSwan akan mempersempit selector atau menolak CHILD SA, dan sebagian subnet tidak akan lewat tunnel.

## Contoh: site A 10.1.0.0/24 ↔ site B 10.2.0.0/24

| | Site A (gateway VPNaaS) | Site B (peer) |
|---|---|---|
| Alamat publik | 203.0.113.10 | 198.51.100.20 |
| IP LAN gateway | 10.1.0.1 | 10.2.0.1 |
| `local_ts` | `10.1.0.0/24` | `10.2.0.0/24` |
| `remote_ts` | `10.2.0.0/24` | `10.1.0.0/24` |

Membuat koneksi di site A:

```bash
curl --fail --silent --show-error -X POST \
  -H "X-API-Key: $API_KEY" -H 'Content-Type: application/json' \
  --data-binary '{"name":"ke-site-b","remote_address":"198.51.100.20","remote_id":"198.51.100.20","local_ts":"10.1.0.0/24","remote_ts":"10.2.0.0/24","psk":"Ganti-Dengan-PSK-Acak-Unik-32","enabled":true}' \
  "$API_BASE/api/connections"
```

Bila site B juga punya subnet kedua 10.20.0.0/24, cukup ubah di site A `remote_ts` menjadi `10.2.0.0/24,10.20.0.0/24` dan di site B `local_ts` menjadi `10.2.0.0/24,10.20.0.0/24`. Contoh konfigurasi strongSwan untuk peer Linux (bukan VPNaaS):

```
connections {
  ke-site-a {
    version = 2
    remote_addrs = 203.0.113.10
    proposals = aes256-sha256-modp2048
    local  { auth = psk  id = 198.51.100.20 }
    remote { auth = psk  id = 203.0.113.10 }
    children {
      ke-site-a-net {
        local_ts  = 10.2.0.0/24,10.20.0.0/24
        remote_ts = 10.1.0.0/24
        esp_proposals = aes256-sha256
        start_action = start
        dpd_action = restart
      }
    }
  }
}
secrets {
  ike-site-a { id-1 = 198.51.100.20  id-2 = 203.0.113.10  secret = "Ganti-Dengan-PSK-Acak-Unik-32" }
}
```

Muat ulang dengan `swanctl --load-all` lalu `swanctl --initiate --child ke-site-a-net`. Proposal di VPNaaS: IKE `aes256-sha256-modp2048` atau `aes128-sha256-modp2048`, ESP `aes256-sha256` atau `aes128-sha256`.

## Route di host LAN atau router

Tunnel yang ESTABLISHED belum berarti host LAN bisa saling menjangkau. Paket dari host di site A ke 10.2.0.0/24 harus sampai ke gateway VPN, bukan ke default gateway internet. Pilih salah satu:

1. **Gateway VPN adalah default gateway LAN** — tidak perlu route tambahan.
2. **Route di router LAN** (disarankan) — tambahkan static route `10.2.0.0/24 via 10.1.0.1` (IP LAN gateway VPN) di router subnet. Semua host ikut otomatis.
3. **Route per host**:

Linux:
```bash
ip route add 10.2.0.0/24 via 10.1.0.1
# permanen di Debian (ifupdown): tambahkan ke stanza interface
#   up ip route add 10.2.0.0/24 via 10.1.0.1
```

Windows (Command Prompt sebagai Administrator; `-p` agar permanen):
```
route -p add 10.2.0.0 mask 255.255.255.0 10.1.0.1
```

OpenStack router (router subnet LAN, bukan gateway VPN):
```bash
openstack router set --route destination=10.2.0.0/24,gateway=10.1.0.1 "$ROUTER_LAN"
```

Lakukan hal yang sama di site B untuk 10.1.0.0/24 via 10.2.0.1. Route harus dua arah; jika hanya satu sisi, ping akan timeout karena balasan tidak kembali ke tunnel.

## OpenStack: port security dan allowed-address-pairs

Neutron port security secara default membuang paket yang keluar dari port VM dengan IP sumber selain IP port tersebut, dan paket masuk ke port dengan IP tujuan yang bukan miliknya. Gateway VPN meneruskan paket dari subnet seberang (sumber 10.2.0.x) keluar NIC LAN (mis. `ens8`), dan menerima balasan yang ditujukan ke 10.2.0.x. Tanpa izin, paket itu hilang diam-diam walaupun counter SA naik.

Izinkan subnet remote pada port LAN gateway VPN:

```bash
# Cari port NIC LAN gateway VPN
openstack port list --server "$NAMA_VM_GATEWAY"
# Izinkan subnet seberang (ulangi untuk setiap CIDR remote_ts)
openstack port set --allowed-address ip-address=10.2.0.0/24 "$PORT_ID_LAN_GATEWAY"
openstack port show "$PORT_ID_LAN_GATEWAY" -c allowed_address_pairs
```

Alternatif (kurang ketat): matikan port security pada port LAN saja, yang juga melepas security group port itu:

```bash
openstack port set --no-security-group --disable-port-security "$PORT_ID_LAN_GATEWAY"
```

Jangan mematikan port security pada port publik. Security group port LAN juga harus mengizinkan trafik dari subnet remote ke host tujuan; demikian pula security group di VM tujuan (masuk dari 10.2.0.0/24).

## Hubungan dengan firewall dan policy

Backend membuat aturan di tabel nftables `inet vpnaas` saja (tabel lain tidak disentuh). Untuk setiap pasangan subnet lokal × remote:

- masuk dari remote ke lokal diterima hanya jika paket datang dari IPsec (`meta ipsec exists`);
- keluar dari lokal ke remote diterima (kemudian dienkripsi oleh policy XFRM);
- SYN TCP dua arah di-clamp MSS ke 1300 agar tidak terjadi fragmentasi/blackhole MTU.

Contoh 2 subnet lokal × 2 subnet remote menghasilkan 4 pasangan, 8 aturan forward dan 8 aturan MSS. Policy global (`/api/policies`) menambah izin di luar pasangan ini; trafik C2S tetap diatur per akun dan tidak bisa memakai policy untuk melompati izinnya. Firewall host lain (iptables/nftables di gateway peer, Windows Firewall di host tujuan) tetap harus mengizinkan trafik.

## NAT-T: sisi mana yang harus terjangkau

IKEv2 memakai UDP 500 dan, bila ada NAT di jalur, UDP 4500 (NAT-T, ESP dibungkus UDP — terlihat sebagai `TUNNEL-in-UDP` di `swanctl --list-sas`).

- Minimal **satu sisi harus punya IP publik** yang menerima UDP 500 dan 4500 (security group/firewall terbuka).
- Sisi yang berada **di balik NAT harus menjadi inisiator**: gateway publik tidak bisa memulai koneksi ke alamat NAT yang tidak meneruskan port. Di peer NAT, set `start_action = start` dan `dpd_action = restart` agar tunnel dibangun dan dipulihkan otomatis.
- Di peer NAT, `local_addrs` (bila diisi) adalah IP privat mesin; `local.id` boleh tetap IP publik NAT agar cocok dengan `remote_id` di VPNaaS. `remote_address` di VPNaaS diisi IP publik NAT peer.
- Jika kedua sisi di balik NAT tanpa port forwarding, tunnel tidak bisa dibangun.

Koneksi VPNaaS dibuat dengan `start_action = none`. `POST /api/connections/{id}/initiate` hanya berguna bila peer dapat dijangkau dari gateway ini.

## Verifikasi

Lakukan dari **host di LAN**, bukan dari gateway (ping IP gateway sendiri tidak membuktikan forwarding):

```bash
# di gateway: tunnel dan selector
swanctl --list-sas
# di host 10.1.0.50 site A
ping -c4 10.2.0.50
curl -m5 http://10.2.0.50/
# di gateway: counter bytes/packets in/out harus naik
swanctl --list-sas | grep -E ' (in|out) '
nft list chain inet vpnaas forward
```

Diagnosa umum:

| Gejala | Penyebab paling sering |
|---|---|
| Tunnel ESTABLISHED, counter `out` naik, `in` tetap 0 | Peer tidak punya route balik atau firewall peer memblok |
| Counter `in` naik di gateway, host tujuan tidak menerima | Port security/allowed-address-pairs OpenStack, atau security group VM tujuan |
| Host tidak mengirim ke gateway sama sekali | Route di host/router LAN belum ada |
| Hanya sebagian subnet yang lewat | Daftar `local_ts`/`remote_ts` tidak dicerminkan di kedua sisi |
| HTTP/SSH macet tetapi ping lancar | MTU; periksa aturan MSS di chain `mss` dan firewall perantara |
