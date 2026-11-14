# Panduan REST API VPNaaS

Panduan ini adalah referensi API backend yang otoritatif. Backend mengelola IKEv2 strongSwan (C2S EAP-MSCHAPv2 dan S2S PSK), SQLite, dan firewall nftables pada satu gateway. Belum ada RBAC, multi-tenant, atau engine OpenVPN/WireGuard. Satu API key memberi akses administratif penuh, termasuk pengambilan password akun.

## 1. Menjalankan API setelah instalasi

`install.sh` memasang aplikasi dan venv di `/opt/vpnaas/backend`, DB di `/var/lib/vpnaas/data.sqlite3`, konfigurasi di `/etc/vpnaas/backend.env`, serta API key root-only mode `0600` di `/etc/vpnaas/api.key`. Installer mengaktifkan service saat boot dan menunggu HTTP health berhasil. Tidak perlu menjalankan Uvicorn manual.

Unit `vpnaas-api.service` berjalan sebagai root karena mengendalikan IPsec/nftables. Wrapper `run` membaca API key; `EnvironmentFile` memuat konfigurasi gateway. `ExecStartPre` menerapkan konfigurasi VPN sebelum Uvicorn mendengarkan **hanya `127.0.0.1:8000`**, dengan access log dimatikan. `Restart=always`, jeda restart 3 detik, dan stdout/stderr ke journald.

```bash
sudo systemctl start vpnaas-api.service
sudo systemctl restart vpnaas-api.service
sudo systemctl status vpnaas-api.service --no-pager
sudo systemctl is-active vpnaas-api.service
sudo systemctl status strongswan.service vpnaas-reconcile.timer --no-pager
sudo journalctl -u vpnaas-api.service -n 100 --no-pager
sudo journalctl -u vpnaas-api.service -f
sudo journalctl -u strongswan.service -u vpnaas-reconcile.service -n 100 --no-pager
sudo ss -lntp 'sport = :8000'
```

`active` pada systemd belum tentu berarti socket HTTP sudah siap. Setelah start/restart, lakukan pemeriksaan readiness berikut dari gateway (Bash). Jika login sebagai root, `sudo` dapat dihapus; Debian minimal belum tentu memasangnya.

```bash
set +x  # jangan aktifkan tracing saat menangani rahasia
API_BASE=http://127.0.0.1:8000
API_KEY=$(sudo cat /etc/vpnaas/api.key)
ready=0
for attempt in {1..90}; do
  if curl --fail --silent --output /dev/null --max-time 2 \
      -H "X-API-Key: $API_KEY" "$API_BASE/api/health"; then
    ready=1
    break
  fi
  sleep 1
done
if [ "$ready" -eq 1 ]; then
  printf 'HTTP API siap\n'
else
  printf 'API belum siap; periksa journald dan listener\n' >&2
fi
```

Health hanya membuktikan proses HTTP dan autentikasi bekerja, **bukan** kesiapan LAN, daemon IPsec, atau tunnel. Periksa `/api/status`, route privat, dan trafik nyata untuk itu. Tidak ada endpoint `/ready`, `/metrics`, atau start/restart service lewat REST.

### Mengakses dari komputer lain

Jangan membuka port 8000 ke internet atau mengganti bind ke `0.0.0.0`. Pilihan paling sederhana: SSH ke gateway, lalu jalankan seluruh contoh di sana. Untuk akses HTTP dari workstation, buat tunnel pada terminal pertama (ganti nama host dengan alias SSH yang sudah dikonfigurasi):

```bash
GATEWAY_SSH=vpnaas-gateway
ssh -N -o ExitOnForwardFailure=yes \
  -L 127.0.0.1:18000:127.0.0.1:8000 "$GATEWAY_SSH"
```

Pada terminal kedua di workstation, baca key lewat SSH tanpa mencetaknya, lalu gunakan port lokal tunnel:

```bash
set +x
GATEWAY_SSH=vpnaas-gateway
API_BASE=http://127.0.0.1:18000
API_KEY=$(ssh "$GATEWAY_SSH" 'sudo cat /etc/vpnaas/api.key')
```

Pembacaan remote memerlukan izin sudo yang sesuai (atau sesi root yang diizinkan); jangan mengendurkan permission file agar pengguna lain bisa membacanya. Jangan menggunakan `echo "$API_KEY"`, `curl -v`, shell tracing, screenshot header, atau menyimpan key/profil/DB/private PKI dalam Git. Contoh `curl -H` dapat mengekspos key sementara kepada inspeksi proses lokal yang berwenang; gunakan gateway/workstation administratif tepercaya. Setelah selesai: `unset API_KEY` dan tutup tunnel. Reinstall mempertahankan key lama; jangan menghapusnya untuk mencoba memperbaiki error autentikasi.

## 2. Konvensi dan seluruh route

Semua **20 operasi bisnis** di bawah memerlukan `X-API-Key`. Header tidak peka huruf besar/kecil. Request POST/PUT CRUD memakai `Content-Type: application/json` dengan objek JSON, bukan array. Respons sukses bisnis selalu HTTP **200**, termasuk create dan delete (bukan 201/204).

| Metode | Path | Fungsi |
|---|---|---|
| GET | `/api/health` | Health HTTP |
| GET | `/api/overview` | Jumlah objek dan status VPN |
| GET | `/api/status` | Status daemon, pool, dan diagnostik route |
| GET | `/api/audit` | Maksimal 500 metadata perubahan terakhir |
| GET | `/api/users` | Seluruh akun dan runtime |
| GET | `/api/users/{ident}` | Satu akun dan runtime |
| POST | `/api/users` | Buat akun |
| PUT | `/api/users/{ident}` | Ubah sebagian field akun |
| DELETE | `/api/users/{ident}` | Hapus akun |
| GET | `/api/users/{ident}/profile` | Unduh profil sensitif |
| GET | `/api/connections` | Seluruh koneksi S2S |
| POST | `/api/connections` | Buat koneksi S2S |
| PUT | `/api/connections/{ident}` | Ubah sebagian field koneksi |
| DELETE | `/api/connections/{ident}` | Hapus koneksi |
| POST | `/api/connections/{ident}/initiate` | Mulai CHILD S2S |
| POST | `/api/connections/{ident}/terminate` | Hentikan IKE S2S |
| GET | `/api/policies` | Seluruh policy global |
| POST | `/api/policies` | Buat policy |
| PUT | `/api/policies/{ident}` | Ubah sebagian field policy |
| DELETE | `/api/policies/{ident}` | Hapus policy |

`ident` adalah ID integer dari respons create/list. ID objek dipakai bersama lintas jenis resource, tidak dijamin berurutan dan **bukan** nomor host VIP. GET detail hanya tersedia untuk `/api/users/{ident}` (404 bila tidak ada); tidak ada GET detail `/api/connections/{ident}` atau `/api/policies/{ident}`, ambil list dan pilih berdasarkan `id`. Tidak ada PATCH, bulk CRUD, pencarian, pagination, total header, atau query filter. List berupa array langsung `[]`, diurutkan `id` naik, tanpa envelope `items/data`. Audit berbeda: urutan `id` turun, dibatasi 500, tanpa cursor/offset. Jangan mengandalkan query parameter yang tidak didukung untuk membatasi hasil.

PUT bersifat **merge parsial**, bukan penggantian penuh: field yang tidak dikirim dipertahankan. Body `{}` juga diterima untuk objek yang ada dan tetap menjalankan apply/revocation. Field tak dikenal ditolak, termasuk `id`, `virtual_ip`, `extra_virtual_ips`, runtime, atau `dns` dalam request CRUD. `enabled` harus boolean JSON `true/false`, bukan string/angka.

### OpenAPI dan halaman dokumentasi bawaan

FastAPI juga mengekspos empat route berikut **tanpa API key** (GET; route bawaan juga menerima HEAD):

```bash
curl --fail --silent --show-error "$API_BASE/openapi.json"
curl --fail --silent --show-error "$API_BASE/docs" --output swagger.html
curl --fail --silent --show-error "$API_BASE/redoc" --output redoc.html
curl --fail --silent --show-error "$API_BASE/docs/oauth2-redirect" --output oauth2-redirect.html
```

`/docs` adalah Swagger UI, `/redoc` adalah ReDoc; `/docs/oauth2-redirect` merupakan helper UI bawaan, **bukan login OAuth VPNaaS**. Halaman UI bisa membutuhkan aset CDN/internet. OpenAPI mencatat header `x-api-key` sebagai parameter (default string kosong), bukan skema bearer/OAuth; isi header pada operasi yang dicoba. Karena implementasi memakai body `dict`, skema OpenAPI generik dan tidak menjelaskan semua validasi bisnis maupun bentuk respons. Tabel field di panduan ini melengkapinya. Jangan mengira header terlihat opsional di OpenAPI berarti API bisnis boleh tanpa key.

## 3. Users: field, CRUD, dan runtime

### Body akun

| Field | Tipe dan aturan | Default POST / perilaku PUT |
|---|---|---|
| `username` | string 1–128 karakter, regex `[A-Za-z0-9_@.:-]{1,128}`; unik pada users | Wajib POST; tidak dikirim pada PUT → tetap |
| `password` | string 8–128 karakter, regex `[A-Za-z0-9_@.!+,:/=-]{8,128}` | Wajib POST; omit atau string kosong pada PUT → password lama |
| `enabled` | boolean | `true`; `false` menonaktifkan akses administratif |
| `allowed_cidrs` | array 1–16 CIDR IPv4, tidak boleh `/0` | Bila dihilangkan: `[VPNAAS_LAN_CIDR]`; bila instalasi belum punya LAN (placeholder `192.0.2.0/24`), memakai subnet LAN privat yang saat ini menempel di NIC non-publik (NIC yang di-attach belakangan). Tanpa LAN privat → 422. Sebaiknya kirim eksplisit |
| `traffic_mode` | string persis `split` atau `full` | `split`; omit PUT mempertahankan mode |
| `max_sessions` | integer JSON 1–3 (bukan string, float, atau boolean) | `3`; omit PUT mempertahankan nilai. `0`, negatif, `>3` → 422 |

CIDR dinormalisasi dengan `strict=False`: misalnya `10.20.0.7/24` disimpan sebagai `10.20.0.0/24`. IPv6 tidak didukung. Default LAN berasal dari konfigurasi instalasi, bukan subnet universal. Jangan gunakan `0.0.0.0/0` dalam `allowed_cidrs`; gunakan `traffic_mode: "full"` untuk internet melalui VPN.

- **split**: selector ke `allowed_cidrs`, tanpa atribut DNS full-tunnel. Klien tetap perlu konfigurasi routing yang benar, terutama Windows; lihat [panduan Windows](windows.md).
- **full**: selector `0.0.0.0/0`, internet keluar melalui interface publik/NAT gateway. `allowed_cidrs` tetap menentukan izin LAN; bukan izin bebas ke seluruh jaringan privat. Range nonpublik lain dan akses ke pool VIP lain diblokir. Pada mode route-auto, grant LAN hanya aktif bila ada route privat yang aman; route default publik tidak cukup. Pengaturan full-tunnel pada klien tetap perlu diterapkan.
- DNS full-tunnel berasal dari `VPNAAS_FULL_DNS`, 1–4 alamat IPv4 dipisahkan koma; default `1.1.1.1,8.8.8.8`. DNS bukan field akun dan tidak bisa disetel melalui endpoint ini. DNS privat juga memerlukan izin/route LAN yang sesuai.

### Contoh CRUD akun

Semua alamat/subnet berikut ilustrasi, bukan konfigurasi deployment. Sesuaikan LAN dengan jaringan sendiri. Password/PSK contoh **bukan kredensial untuk digunakan**; ganti dengan rahasia acak unik yang memenuhi aturan karakter. Jangan menyimpan body berisi rahasia dalam history/log atau file repo; gunakan input/file privat mode `0600` untuk otomasi produksi.

```bash
curl --fail --silent --show-error -X GET \
  -H "X-API-Key: $API_KEY" "$API_BASE/api/users"

USER_JSON=$(curl --fail --silent --show-error -X POST \
  -H "X-API-Key: $API_KEY" -H 'Content-Type: application/json' \
  --data-binary '{"username":"contoh-operator","password":"Ganti-Dengan-Rahasia-Acak-32","enabled":true,"allowed_cidrs":["10.20.0.0/24"],"traffic_mode":"split"}' \
  "$API_BASE/api/users")
USER_ID=$(printf '%s' "$USER_JSON" | python3 -c 'import json,sys; print(json.load(sys.stdin)["id"])')

# Edit izin dan mode tanpa mengubah password.
curl --fail --silent --show-error -X PUT \
  -H "X-API-Key: $API_KEY" -H 'Content-Type: application/json' \
  --data-binary '{"allowed_cidrs":["10.20.0.42/32"],"traffic_mode":"full"}' \
  "$API_BASE/api/users/$USER_ID"

# Mengganti password: kirim nilai baru yang tidak kosong.
curl --fail --silent --show-error -X PUT \
  -H "X-API-Key: $API_KEY" -H 'Content-Type: application/json' \
  --data-binary '{"password":"Ganti-Dengan-Rahasia-Baru-32"}' \
  "$API_BASE/api/users/$USER_ID"

# Menonaktifkan akun; ini bukan perintah disconnect sementara.
curl --fail --silent --show-error -X PUT \
  -H "X-API-Key: $API_KEY" -H 'Content-Type: application/json' \
  --data-binary '{"enabled":false}' "$API_BASE/api/users/$USER_ID"
```

Jangan mengirim placeholder `***`/`[REDACTED]` sebagai password saat edit: itu bukan sinyal mempertahankan password. Omit field adalah cara yang disarankan. Nilai credential falsy (termasuk `""`/`null`) diabaikan implementasi, tetapi jangan mengandalkan tipe non-string; POST tanpa credential yang valid tetap gagal.

### Respons akun dan runtime

POST/PUT mengembalikan objek dengan **semua** field berikut (tanpa password): `id` integer, `username` string, `enabled` boolean, `allowed_cidrs` array string, `traffic_mode` string, `max_sessions` integer 1–3, `virtual_ip` string IPv4, `extra_virtual_ips` array string IPv4 (read-only, panjang `max_sessions-1`). GET list dan GET detail `/api/users/{ident}` menambahkan field runtime pada **setiap** akun:

| Field tambahan GET list/detail | Bentuk / arti |
|---|---|
| `runtime_status` | `Active`, `Down`, atau `Unknown` |
| `session_count` | integer jumlah IKE ESTABLISHED dengan minimal satu CHILD INSTALLED; `null` bila Unknown. UI menampilkan `session_count/max_sessions` |
| `virtual_ips` | array string VIP yang teramati pada seluruh sesi cocok, bukan hanya sesi aktif; unik dan terurut |
| `sessions` | array objek sesi cocok; kosong bila tidak ada atau Unknown |

Setiap `sessions[]` mempunyai `ike_id` string atau null, `ike_state` string atau null, `remote_address` string atau null, `virtual_ips` array string, dan `children` array. Hanya CHILD berstatus INSTALLED dimasukkan ke `children`; setiap anak mempunyai `child_id` string atau null, `state: "INSTALLED"`, `bytes_in` integer, `bytes_out` integer. Counter adalah snapshot byte daemon, bukan bandwidth per detik. Jangan menganggap ID IKE/CHILD sebagai integer JSON.

`Active` memerlukan IKE **ESTABLISHED** dan CHILD **INSTALLED**, dicocokkan dengan identitas EAP terautentikasi (fallback nama konfigurasi bila identitas tidak tersedia). `Down` berarti snapshot valid tanpa pasangan aktif, bukan sekadar `enabled=false`. `Unknown` berarti daemon gagal/timeout, output tidak lengkap/rusak, atau dry-run; nilainya `session_count:null`, `virtual_ips:[]`, `sessions:[]`. `enabled` hanya pengaturan administratif, bukan bukti koneksi. POST/PUT tidak menyertakan snapshot runtime; lakukan GET list/detail lagi.

### Batas sesi bersamaan (`max_sessions`)

strongSwan tidak membatasi jumlah sesi EAP per akun, jadi backend menegakkannya sendiri:

- Konfigurasi `user-<id>` memakai `unique = never` (sesi kedua tidak lagi menendang sesi pertama) dan `pools = pool-<id>,pool-<id>-2,...`: satu pool satu alamat per slot sesi. `virtual_ip` adalah VIP sesi pertama (yang ada di profil); `extra_virtual_ips` untuk sesi ke-2 dan ke-3. Semua VIP akun mendapat ACL, NAT dan clamp MSS yang sama. Setiap slot memakai satu lease dari pool /24, sehingga kapasitas berkurang; create/PUT yang tidak mendapat cukup lease → 409 tanpa perubahan.
- Task latar di lifespan FastAPI, setiap 5 detik (`VPNAAS_SESSION_LIMIT_INTERVAL`), membaca snapshot lengkap `swanctl --list-sas --raw`, mengelompokkan IKE ESTABLISHED berdasarkan identitas EAP terautentikasi. Bila jumlah endpoint (`remote-host:port`) melebihi `max_sessions`, SA **terbaru** dihentikan dengan `swanctl --terminate --ike-id <uniqueid> --force`; `max_sessions` sesi tertua tetap hidup. Dua SA dari host:port yang sama (overlap reauth make-before-break) dihitung satu sesi.
- Setiap penghentian ditulis ke journald (`vpnaas-sessions WARNING session limit: user id=... terminated IKE_SA #...`) dan audit `action:"session_limit"`. Dry-run, daemon gagal/timeout, atau snapshot rusak tidak menghentikan apa pun; kegagalan tidak mematikan API. Nonaktifkan task dengan `VPNAAS_SESSION_LIMIT=0`.
- Klien surplus bisa terhubung sebentar (≤ ~5 detik) sebelum dihentikan; batas ini bukan penolakan pada saat IKE_AUTH. Menurunkan `max_sessions` lewat PUT juga merevoke sesi akun (seperti PUT lain), lalu klien harus reconnect.
- Database lama dimigrasi otomatis (schema v2): akun tanpa field mendapat `max_sessions: 3` dan dua VIP tambahan; bila pool tidak cukup, nilai dipangkas dan dicatat di journal.

### Pool dan virtual IP

Installer memilih satu `/24` bebas konflik dari rentang `172.31.201.0/24` sampai `172.31.250.0/24`, lalu menyimpannya sebagai `VPNAAS_POOL_CIDR`. Gunakan `pool_cidr` dari status untuk mengetahui pool server, jangan hardcode salah satu kandidat. VIP dialokasikan dari host bebas, disimpan per akun, dan tidak dihitung dari ID. Kapasitas 254 lease; tiap akun memakai `max_sessions` lease (default 3, jadi ±84 akun default; akun disabled tetap memegang lease). Edit/restart/reinstall mempertahankan VIP; menghapus akun membebaskan lease. Perubahan pool bukan CRUD biasa: perlu backup, migrasi, dan reconnect; lihat [pool VIP](pool-vip.md).

### Profil akun: satu-satunya respons dengan password

Jalankan sebelum menghapus akun contoh. Profil juga bisa diambil untuk akun disabled; keberhasilan unduh tidak membuktikan akun boleh terkoneksi.

```bash
umask 077
PROFILE_FILE="user-$USER_ID.json"
curl --fail --silent --show-error -X GET \
  -H "X-API-Key: $API_KEY" \
  --output "$PROFILE_FILE" "$API_BASE/api/users/$USER_ID/profile"
# Jangan cat file ini ke terminal/log. Kirim hanya ke pemilik melalui kanal aman.

# Hapus hanya akun contoh milik sendiri jika sudah selesai.
curl --fail --silent --show-error -X DELETE \
  -H "X-API-Key: $API_KEY" "$API_BASE/api/users/$USER_ID"
rm -f -- "$PROFILE_FILE"
```

Respons profil JSON memuat `username`, **`password` plaintext**, `traffic_mode`, `server`, `server_id`, `virtual_ip`, `allowed_cidrs`, `ca_certificate`; full saja menambahkan `dns` array string IPv4. `server`/`server_id` memakai `VPNAAS_PUBLIC_IP` instalasi, bukan alamat loopback API. `ca_certificate` adalah PEM CA publik (string kosong bila file CA tidak ada), **bukan** private key. Tidak ada `id`, `enabled`, atau runtime di profil. Header: `Cache-Control: no-store` dan `Content-Disposition: attachment; filename="Profil-VPN-<username>.json"` bila diunduh lewat UI (API langsung: `user-<ident>.json`). No-store tidak mengenkripsi file di disk dan tidak mencegah logging oleh klien. API key maupun private CA/server key tidak dikembalikan.

## 4. Connections: S2S PSK

| Field body | Tipe / aturan | Default POST |
|---|---|---|
| `name` | string regex aman sama seperti username; unik pada connections | Wajib |
| `remote_address` | string alamat IPv4 peer; bukan hostname/URL | Wajib |
| `remote_id` | string regex aman sama seperti username | Alamat `remote_address` bila kosong/tidak diberikan |
| `local_ts` | string CIDR IPv4, dinormalisasi | `VPNAAS_LAN_CIDR` |
| `remote_ts` | string CIDR IPv4, dinormalisasi | Wajib |
| `psk` | string regex credential sama seperti password | Wajib; omit/kosong PUT mempertahankan PSK |
| `enabled` | boolean | `true` |

`remote_id` harus sesuai identitas peer, dan selector di peer harus saling berbalik. `/0` tidak dilarang validator selector koneksi, tetapi jangan memberi selector luas tanpa desain routing/firewall yang tepat. Tidak ada field port, proposal, versi IKE, DNS, atau username pada koneksi; parameter kriptografi ditetapkan backend. Create hanya memuat konfigurasi (`start_action=none`), bukan otomatis membangun tunnel.

```bash
curl --fail --silent --show-error -X GET \
  -H "X-API-Key: $API_KEY" "$API_BASE/api/connections"

CONNECTION_JSON=$(curl --fail --silent --show-error -X POST \
  -H "X-API-Key: $API_KEY" -H 'Content-Type: application/json' \
  --data-binary '{"name":"contoh-cabang","remote_address":"192.0.2.10","remote_id":"cabang.example","local_ts":"10.20.0.0/24","remote_ts":"10.30.0.0/24","psk":"Ganti-Dengan-PSK-Acak-Unik-32","enabled":true}' \
  "$API_BASE/api/connections")
CONNECTION_ID=$(printf '%s' "$CONNECTION_JSON" | python3 -c 'import json,sys; print(json.load(sys.stdin)["id"])')

curl --fail --silent --show-error -X PUT \
  -H "X-API-Key: $API_KEY" -H 'Content-Type: application/json' \
  --data-binary '{"remote_ts":"10.30.1.0/24"}' \
  "$API_BASE/api/connections/$CONNECTION_ID"

# Tanpa body. Jalankan initiate hanya setelah peer nyata siap.
curl --fail --silent --show-error -X POST \
  -H "X-API-Key: $API_KEY" "$API_BASE/api/connections/$CONNECTION_ID/initiate"
curl --fail --silent --show-error -X POST \
  -H "X-API-Key: $API_KEY" "$API_BASE/api/connections/$CONNECTION_ID/terminate"

curl --fail --silent --show-error -X DELETE \
  -H "X-API-Key: $API_KEY" "$API_BASE/api/connections/$CONNECTION_ID"
```

`192.0.2.10` adalah alamat dokumentasi; initiate contoh tidak akan berhasil tanpa menggantinya dengan peer yang dapat dijangkau dan mengonfigurasi kedua sisi. Respons list/create/update memiliki `id`, `name`, `remote_address`, `remote_id`, `local_ts`, `remote_ts`, `enabled`; **tidak memiliki `psk`**. Respons action adalah `{"ok":true,"output":"..."}` dengan output string swanctl. Initiate menjalankan CHILD `net-<ident>`; terminate menghentikan IKE `site-<ident>` tanpa menonaktifkan objek. Initiate pada koneksi disabled menghasilkan 409; terminate tanpa SA dapat menghasilkan 502, jangan mengasumsikannya idempoten.

Action memakai timeout swanctl 12 detik dan subprocess 18 detik. HTTP 200 action bukan bukti trafik LAN end-to-end: periksa status IKE/CHILD, counter kedua peer, dan akses host di balik gateway. Tidak ada endpoint initiate/terminate akun C2S; klien memulai koneksi C2S. Edit/disable/delete akun atau koneksi mencabut SA terkait sebelum apply; **bahkan edit tanpa perubahan dapat memutus sesi**.

## 5. Policies: izin forwarding global

| Field body | Tipe / aturan | Default POST |
|---|---|---|
| `name` | string regex aman sama seperti username; unik pada policies | Wajib |
| `source_cidr` | string CIDR IPv4, dinormalisasi | Wajib |
| `destination_cidr` | string CIDR IPv4, dinormalisasi | Wajib |
| `protocol` | string `all`, `tcp`, `udp`, atau `icmp` | `all` |
| `enabled` | boolean | `true` |

Policy adalah rule **accept** forwarding global, bukan konfigurasi tunnel, bukan deny rule, dan tidak mempunyai port, priority, action, user_id, atau connection_id. `/0` diterima di CIDR policy, tetapi izin luas berisiko. Mandatory ACL sumber pool C2S diproses lebih dahulu, sehingga policy global tidak membypass `allowed_cidrs` akun. Menghapus policy tidak menjamin memutus semua flow established; ini bukan endpoint revocation SA.

```bash
curl --fail --silent --show-error -X GET \
  -H "X-API-Key: $API_KEY" "$API_BASE/api/policies"

POLICY_JSON=$(curl --fail --silent --show-error -X POST \
  -H "X-API-Key: $API_KEY" -H 'Content-Type: application/json' \
  --data-binary '{"name":"contoh-izin-icmp","source_cidr":"10.30.0.0/24","destination_cidr":"10.20.0.0/24","protocol":"icmp","enabled":true}' \
  "$API_BASE/api/policies")
POLICY_ID=$(printf '%s' "$POLICY_JSON" | python3 -c 'import json,sys; print(json.load(sys.stdin)["id"])')

curl --fail --silent --show-error -X PUT \
  -H "X-API-Key: $API_KEY" -H 'Content-Type: application/json' \
  --data-binary '{"enabled":false,"protocol":"tcp"}' "$API_BASE/api/policies/$POLICY_ID"

curl --fail --silent --show-error -X DELETE \
  -H "X-API-Key: $API_KEY" "$API_BASE/api/policies/$POLICY_ID"
```

Respons list/create/update policy mempunyai `id`, `name`, `source_cidr`, `destination_cidr`, `protocol`, `enabled`. Semua DELETE CRUD mengembalikan `{"deleted":true}`; DELETE ulang menghasilkan 404.

## 6. Health, status, overview, dan audit

Keempat GET ini tanpa body:

```bash
curl --fail --silent --show-error -X GET \
  -H "X-API-Key: $API_KEY" "$API_BASE/api/health"
curl --fail --silent --show-error -X GET \
  -H "X-API-Key: $API_KEY" "$API_BASE/api/status"
curl --fail --silent --show-error -X GET \
  -H "X-API-Key: $API_KEY" "$API_BASE/api/overview"
curl --fail --silent --show-error -X GET \
  -H "X-API-Key: $API_KEY" "$API_BASE/api/audit"
```

### Bentuk respons

- **health**: `{"status":"ok"}`.
- **overview**: `connections`, `users`, `policies` adalah integer jumlah seluruh objek, termasuk disabled; `enabled_connections` integer jumlah koneksi enabled, bukan jumlah tunnel aktif; `vpn` objek yang sama dengan status. Jika status gagal, overview juga bisa 503.
- **status** dalam operasi nyata:
  - `pool_cidr`: string CIDR pool persisten server.
  - `raw`: string output `swanctl --list-sas`.
  - `connections`: string output `swanctl --list-conns` (bukan array CRUD connections).
  - `pools`: string output `swanctl --list-pools`.
  - `backend`: string `strongSwan swanctl`.
  - `network`: hanya bila `VPNAAS_ROUTE_AUTO=1`; objek berisi `public_interface` (string/null), `private_routes` (array), `private_ready` (boolean), `mode` (`kernel-route-auto`). Tiap `private_routes[]` berisi `cidr` string, `interface` string/null, `ready` boolean. Daftar dihitung dari CIDR akun **enabled**, bukan seluruh selector S2S. `private_ready` adalah semua grant punya route aman; jika tidak ada grant, nilainya true. Ini bukan hasil ping host LAN.
- **audit**: array objek dengan `id` integer, `timestamp` string SQLite `CURRENT_TIMESTAMP` (UTC, bentuk `YYYY-MM-DD HH:MM:SS`, tanpa suffix zona), `action` string `create/update/delete/session_limit`, `resource` string `users/connections/policies`, `resource_id` integer ID objek. Audit mencatat CRUD sukses setelah apply dan penghentian sesi surplus oleh batas `max_sessions` (`session_limit`, `resource_id` = ID akun); tidak merekam login gagal, read, download profil, initiate/terminate, atau payload/credential. Maksimal 500 terbaru; bukan histori lengkap dengan pagination.

Mode `VPNAAS_DRY_RUN=1` dipakai pengujian, bukan bukti daemon nyata. Status mode ini **hanya** `{"raw":"test mode (not daemon status)","connections":""}` dan runtime akun Unknown. Jangan membuat UI menganggap field status nyata selalu tersedia pada dry-run.

## 7. Autentikasi, validasi, dan error

Error terkontrol memakai objek JSON `{"detail":"pesan"}`. Tidak ada envelope error lain atau array rincian validasi input. Contoh aman untuk memeriksa 401, tanpa menampilkan key:

```bash
curl --silent --show-error -i "$API_BASE/api/health"
# HTTP 401; body: {"detail":"Unauthorized"}
```

| HTTP | `detail` | Kondisi |
|---|---|---|
| 401 | `Unauthorized` | Header hilang, kosong, atau tidak cocok |
| 404 | `Not found` | ID tidak ada pada resource yang diminta |
| 409 | `Name already exists` | Username/nama sudah dipakai dalam jenis resource yang sama |
| 409 | `VIP pool exhausted (254 usable hosts; each session slot needs one)` | Lease kosong kurang dari jumlah slot `max_sessions`; user tidak disisipkan/diubah |
| 409 | `Connection disabled` | Initiate pada koneksi nonaktif |
| 409 | `User VIP missing; migrate database first` | Data lama belum mempunyai VIP saat profil/render membutuhkannya |
| 409 | `Invalid persisted user VIP` | VIP tersimpan tidak valid bagi pool saat ini |
| 422 | `Invalid request` | Validasi FastAPI: JSON rusak, body bukan objek, ID bukan integer, body wajib tidak ada, tipe header tidak sesuai |
| 422 | `Unknown fields` | Body berisi field di luar daftar resource |
| 422 | `traffic_mode must be split or full` | Mode eksplisit bukan nilai yang diizinkan |
| 422 | `max_sessions must be an integer 1..3` | `max_sessions` bukan integer 1–3 |
| 422 | `Invalid fields; credentials must be 8-128 safe printable characters` | Field wajib hilang/format salah, CIDR tidak valid, boolean salah, credential tidak valid, atau validasi bisnis lainnya; pesan generik ini tidak selalu berarti password penyebabnya |
| 502 | `VPN configuration apply failed; previous configuration restored` | Penerapan konfigurasi/nft gagal |
| 502 | `Unable to revoke existing VPN session` | Penghentian SA saat mutasi gagal |
| 502 | `VPN action failed; inspect status and strongSwan journal` | Initiate/terminate gagal/timeout |
| 503 | `strongSwan status unavailable` | Pembacaan status daemon atau diagnostik route gagal |

Path yang tidak terdaftar memakai 404 framework `{"detail":"Not Found"}` (kapitalisasi berbeda); metode salah pada path yang ada memakai 405 `{"detail":"Method Not Allowed"}`. Error tak tertangani masih mungkin menjadi 500/non-JSON; klien harus menangani status dan kegagalan parsing, bukan menganggap semua kegagalan mengikuti tabel. Pada contoh digunakan `curl --fail`: exit code nonzero untuk HTTP error; untuk membaca body error gunakan `curl --silent --show-error -i` tanpa `--fail`, tetap jangan gunakan verbose/tracing.

Validasi sengaja tidak mengembalikan input atau secret. Respons CRUD biasa menghilangkan password/PSK, bukan menggantinya dengan mask. Field credential hanya boleh dikirim saat create atau perubahan rahasia, bukan hasil menyalin ulang respons list. Secret tetap tersimpan dalam DB dan konfigurasi root-only; redaksi respons bukan hashing atau enkripsi at-rest.

### Efek mutasi dan pemulihan

CRUD melakukan validasi, perubahan SQLite, apply swanctl/nft, audit, lalu commit. Pada kegagalan terjadi rollback transaksi; apply berupaya memulihkan konfigurasi lama. Penghentian sesi yang sudah terjadi tidak dapat dibatalkan oleh rollback, dan timeout/perintah OS yang gagal tak terduga dapat menghasilkan 500. Pesan 502 bukan jaminan semua efek runtime sudah pulih: periksa status/journal sebelum mencoba ulang. Tidak ada idempotency key; setelah koneksi HTTP putus, baca list sebelum mengulang create agar tidak membuat asumsi salah. Operasi PUT/DELETE akun dan koneksi selalu mencoba revoke SA terkait. Policy tidak mempunyai revoke SA khusus.

Bila API belum siap, mulai dari `journalctl -u vpnaas-api`, listener loopback, strongSwan, lalu `/api/status`. Bila `private_ready=false`, perbaiki route/NIC privat dari platform, bukan membuka grant `0.0.0.0/0`. Timer reconciler menyesuaikan firewall untuk perubahan route tanpa memuat ulang swanctl atau memutus SA. Jangan mengubah langsung DB/pool/key saat service berjalan untuk menutupi masalah. Panduan lanjutan: [instalasi dan operasi](instalasi.md), [jaringan privat](jaringan.md), [pool VIP dan migrasi](pool-vip.md), [Windows](windows.md).
