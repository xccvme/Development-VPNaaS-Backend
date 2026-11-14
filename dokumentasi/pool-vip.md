# Pool VIP per server

Pada install pertama, `/opt/vpnaas/backend/pool.py` memilih **satu** subnet /24 dari `172.31.201.0/24` sampai `172.31.250.0/24` dengan `secrets.choice` (random kriptografis). Kandidat yang bertumpang tindih dengan route IPv4 non-default di semua table, LAN konfigurasi, grant/selector/policy DB, lease DB atau pool strongSwan aktif tidak dipakai. Default route bukan konflik; jika semua kandidat habis, installer berhenti dengan error. Tidak ada koordinasi global antarmesin: server berbeda masih bisa memilih subnet sama bila jaringan mereka belum saling terlihat. Tentukan rancangan route sebelum menggabungkan server.

Hasil dipersistenkan sebagai `VPNAAS_POOL_CIDR` di `/etc/vpnaas/backend.env` mode 0600 dengan lock dan replace atomik. Jalankan ulang script/installer tidak memilih ulang, bahkan bila route kemudian berubah. Operator harus menangani konflik baru secara eksplisit, bukan membiarkan subnet klien berganti diam-diam. Script tersedia kembali dari payload installer; tidak membutuhkan layanan OpenVPN atau WireGuard.

User mendapat `virtual_ip` tersimpan di body SQLite. Alokasi mencari host bebas .1 sampai .254, tidak bergantung ID autoincrement global; user ID besar tetap aman. User nonaktif tetap memiliki alamat; penghapusan membebaskan alamat setelah revokasi sesi. Jika 254 alamat sudah terpakai, create membalas HTTP 409 tanpa menyimpan user setengah jadi. VIP tidak dapat dipilih klien melalui API. Render swanctl, ACL nftables, profil dan status memakai subnet/lease yang sama. `pool_cidr` tersedia di status dan `virtual_ip` di user/profil.

## Upgrade dari pool lama

Installer membuat backup root-only di `/var/backups/vpnaas/<timestamp>/` sebelum mengubah konfigurasi/DB. Sesi user lama yang belum memiliki lease persisten diterminasi secara terarah dengan `swanctl --terminate --ike user-ID`. API dan timer reconcile dihentikan sebelum source baru diekstrak, agar tidak terjadi migrasi dengan environment lama. Saat startup, setiap user tanpa lease diberi alamat baru; username, password, enabled, mode dan allowed_cidrs tetap utuh. User perlu reconnect dan unduh ulang profil untuk melihat VIP baru. Tidak ada restart daemon strongSwan/global nft flush untuk migrasi ini.

Jangan hanya mengganti `VPNAAS_POOL_CIDR` pada server yang sudah berisi lease. Startup menolak lease di luar subnet atau duplikat. Untuk migrasi operator berikutnya: backup konsisten DB/env/PKI; hentikan API/reconcile; cabut sesi user terkait; pilih subnet bebas; ubah env dan seluruh lease secara transaksional; uji `nft --check`, reload melalui API/apply, lalu sambungkan klien lagi. Untuk rollback pulihkan DB, env dan konfigurasi dari backup yang sama; jangan mencampur lease lama dengan pool baru.

Lihat [tuning kernel dan jaringan](tuning-kernel-network.md) untuk MTU/MSS, offload, verifikasi dan batas kesiapan engine alternatif.
