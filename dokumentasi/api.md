# API

Semua `/api/*` memakai header `X-API-Key`; key0600 `/etc/vpnaas/api.key`. Respons list selalu array. Password/PSK tidak ada dalam list/create/update normal. Profil download sensitif, no-store, berisi password dan CA publik. Jangan log payload profil.

- GET health → status ok; GET overview → counts dan VPN.
- GET/POST `/api/users`, PUT/DELETE `/api/users/{id}`. username, password8–128 karakter aman, enabled boolean, allowed_cidrs array IPv4, traffic_mode split(default)/full. PUT parsial, password kosong mempertahankan lama. `/0` di allowed_cidrs ditolak.
- GET `/api/users/{id}/profile` → server/server_id dari IP instalasi, username/password, virtual_ip, allowed_cidrs, CA, mode; full juga DNS.
- GET/POST `/api/connections`, PUT/DELETE `/{id}`: name, remote_address IPv4, remote_id, local_ts, remote_ts, psk, enabled. POST `/{id}/initiate` atau `/terminate` mengontrol swanctl nyata.
- GET/POST `/api/policies`, PUT/DELETE `/{id}`: name, source_cidr, destination_cidr, protocol(all/tcp/udp/icmp), enabled. Policy global tidak melewati ACL mandatory C2S.
- GET status → raw SAs/connections/pools dan network diagnostics; GET audit → metadata operasi tanpa rahasia.

Users runtime Active hanya jika authenticated IKE ESTABLISHED + CHILD INSTALLED; Down jika snapshot valid tanpa SA, Unknown jika daemon gagal dibaca. enabled bukan indikator tersambung. Perubahan akun/koneksi mencabut SA terkait. Fixed VIP10.250.0.(globalID+1), batas global ID253; kapasitas PoC ini termasuk ID objek lain.

EAP discovery pertama meminta identitas; kandidat dummy tidak punya pool/CHILD dan mensyaratkan grup mustahil. Kandidat per-user memilih identitas EAP yang terautentikasi, bukan IKE IDi bebas klien. Jangan mengubah semua eap_id ke %any atau menambah grup/RADIUS tanpa mengaudit seleksi. strongSwan6.0.1 memerlukan paket Debian libcharon-extauth-plugins untuk EAP-MSCHAPv2; extra-plugins saja tidak cukup.

Validation422, auth401, not-found404, duplicate409, apply failure502. Audit dan validation error tidak echo credential. Apply nyata memakai swanctl/nft, bukan seed telemetry. S2S peer end-to-end belum termasuk pengujian test2.
