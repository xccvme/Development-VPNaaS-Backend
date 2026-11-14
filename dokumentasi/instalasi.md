# Instalasi dan operasi

## Siapkan Debian 13

Gunakan VM khusus gateway, akses apt/PyPI, dan IPv4 publik. Perintah berikut memakai `sudo`; jika login sebagai `root`, hapus `sudo` (Debian minimal belum tentu memasangnya).

Update sistem dahulu, sebelum clone atau menjalankan `install.sh`:

```sh
sudo apt-get update && sudo apt-get upgrade -y
sudo apt-get install -y ca-certificates git
```

Jika pembaruan kernel memerlukan reboot, reboot dan login kembali sebelum melanjutkan.

## Clone repo privat dan install

Akun GitHub harus memiliki akses ke repo. Gunakan credential helper yang sudah terautentikasi, atau isi username GitHub dan PAT saat Git meminta password. PAT harus memiliki akses baca repo ini. Jangan memasukkan token ke URL atau menyimpannya dalam dokumentasi.

```sh
git clone https://github.com/xccvme/Development-VPNaaS-Backend.git
cd Development-VPNaaS-Backend
chmod +x install.sh
sudo bash install.sh
```

Installer memuat source aplikasi di dalam script; tidak perlu Docker atau input interaktif saat instalasi. Paket Debian dan Python tetap diunduh dari internet. Installer membuat CA/sertifikat server, venv, SQLite kosong, API key acak, unit `vpnaas-api`, dan timer `vpnaas-reconcile`.

Pada instalasi baru, interface publik dan IPv4 sumber dideteksi dari route ke `1.1.1.1`. Jika IPv4 tersebut bukan alamat publik (misalnya server di balik NAT), installer berhenti: tentukan `PUBLIC_IP` aktual secara eksplisit dan pastikan forwarding VPN di platform benar. Installer tidak mencari IP eksternal melalui layanan pihak ketiga.

## Variabel opsional

Instalasi normal tidak perlu variabel. Nilai di awal script dapat diedit atau diberikan lewat environment: `PUBLIC_IP`, `PUBLIC_IF`, `LAN_CIDR`, `LAN_IF`, `LAN_IP`, `FULL_DNS`. Nilai kosong mempertahankan konfigurasi lama bila ada, atau memakai hasil deteksi/default. DNS default `1.1.1.1,8.8.8.8`.

Contoh mengganti DNS tanpa mengedit script:

```sh
sudo env FULL_DNS='1.1.1.1,8.8.8.8' bash install.sh
```

Untuk NAT, ganti placeholder berikut dengan IPv4 publik aktual dan nama interface yang benar:

```sh
sudo env PUBLIC_IP='<IPv4-publik-aktual>' PUBLIC_IF='<interface-publik>' bash install.sh
```

Saat memakai sudo, letakkan assignment **setelah `sudo env`** agar diteruskan ke installer, bukan `PUBLIC_IP=... sudo bash install.sh` yang dapat dibuang oleh kebijakan sudo. Sebagai root, gunakan `env PUBLIC_IP='...' bash install.sh`.

NIC privat boleh dipasang sesudah instalasi. Tanpa NIC privat, installer menyimpan penanda LAN `192.0.2.0/24`, bukan izin akun siap pakai. Jika `allowed_cidrs` tidak dikirim, API mencari LAN privat aktual; bila belum ada, create akun mengembalikan 422. Kirim CIDR eksplisit jika ingin menyiapkan akun sebelum NIC dipasang. Tentukan `allowed_cidrs` akun sesuai subnet tujuan; akses LAN ditolak sampai ada route privat yang sesuai. Setelah NIC mendapat IP/route dari platform, timer menyesuaikan firewall/NAT tanpa reinstall. Variabel LAN menentukan default form/API, bukan mengunci interface pada mode route-auto. Lihat [mekanisme NIC privat](jaringan.md).

## Firewall dan path penting

Buka **UDP 500/4500** pada firewall platform; izinkan ESP (IP protocol 50) bila tanpa NAT-T. API hanya mendengarkan di **`127.0.0.1:8000`**. Jangan membuka port 8000 atau mem-publish API ke internet; akses UI ke backend tetap melalui jalur lokal/SSH yang sesuai.

- Aplikasi/venv: `/opt/vpnaas/backend`
- Database: `/var/lib/vpnaas/data.sqlite3`
- API key backend: `/etc/vpnaas/api.key`, mode `0600`, milik root; UI satu VM membaca file ini, tidak perlu menyalin key
- Konfigurasi: `/etc/vpnaas/backend.env`, mode `0600`, milik root
- CA private key: `/var/lib/vpnaas/ca-key.pem`
- CA publik: `/etc/swanctl/x509ca/ca.pem`
- Server cert/key: `/etc/swanctl/x509/server.pem`, `/etc/swanctl/private/server-key.pem`

## Pemeriksaan dan instalasi ulang

```sh
sudo systemctl status vpnaas-api strongswan vpnaas-reconcile.timer
sudo journalctl -u vpnaas-api -u vpnaas-reconcile -n 100 --no-pager
sudo ss -lntp 'sport = :8000'
sudo swanctl --list-sas
sudo nft list table inet vpnaas
```

Pastikan listener API hanya `127.0.0.1:8000`. Daftar SA bisa kosong sebelum klien VPN terhubung. Service memakai `Restart=always`, request access log mati, stdout/stderr masuk journald. Root diperlukan untuk kontrol IPsec/nft.

Menjalankan ulang `sudo bash install.sh` menjaga DB, API key, dan seluruh PKI. PKI tidak lengkap menghentikan installer; pulihkan backup, jangan menghapus key secara acak. Perubahan IP publik memerlukan sertifikat baru oleh operator; perubahan NIC privat tidak memerlukan reinstall.

Ini single-gateway PoC, belum isolasi multi-tenant/RBAC/HA. Backup DB serta PKI/key lewat saluran terenkripsi, jangan commit.

Installer tidak flush nft ruleset, tidak mengubah INPUT/OUTPUT/SSH atau konfigurasi DHCP/QGA. Forwarding chain milik VPNaaS dengan policy drop dapat berpengaruh pada forwarding lain; pakai VM khusus gateway. Jangan menaruh konfigurasi swanctl tak terkait di VM ini: `--load-all --clear` memuat ulang credentials/pools global.

Uninstall manual hanya setelah backup: stop/disable unit dan timer milik VPNaaS, hapus tabel `inet vpnaas`, snippet `conf.d/vpnaas.conf`, serta unit/sysctl milik VPNaaS. Jangan flush tabel lain. Evaluasi forwarding sebelum menonaktifkannya.
