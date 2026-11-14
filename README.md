# VPNaaS backend

API IKEv2 strongSwan 6 untuk Debian 13. Gunakan VM khusus gateway dengan akses internet dan IPv4 publik.

## Instalasi cepat

Update sistem **sebelum clone dan menjalankan installer**:

```sh
sudo apt-get update && sudo apt-get upgrade -y
sudo apt-get install -y ca-certificates git
git clone https://github.com/xccvme/Development-VPNaaS-Backend.git
cd Development-VPNaaS-Backend
chmod +x install.sh
sudo bash install.sh
```

Jika sudah login sebagai `root`, hapus `sudo` dari perintah di atas; Debian minimal belum tentu memasang sudo. Repo bersifat privat: gunakan akun GitHub yang diberi akses dan credential helper atau masukkan PAT saat Git meminta password. Jangan menaruh token di URL clone.

Installer berjalan tanpa input interaktif, mengunduh paket Debian/Python, lalu mendeteksi IPv4 dan interface publik pada instalasi baru. Untuk server di balik NAT, tentukan `PUBLIC_IP` secara eksplisit; lihat [panduan instalasi](dokumentasi/instalasi.md). NIC privat boleh dipasang belakangan tanpa reinstall.

Buka **UDP 500/4500** pada firewall platform. API tetap di **`127.0.0.1:8000`**, jangan diekspos ke publik. API key backend berada di `/etc/vpnaas/api.key` (root-only); UI satu VM membaca file ini.

## Dokumentasi

- [Instalasi, variabel opsional, dan operasi](dokumentasi/instalasi.md)
- [Panduan REST API lengkap: operasi service, autentikasi, endpoint, dan contoh curl](dokumentasi/rest-api.md)
- [NIC privat dipasang belakangan](dokumentasi/jaringan.md)
- [Panduan Windows](dokumentasi/windows.md)
- [Pool VIP acak per server dan migrasi](dokumentasi/pool-vip.md)
- [Tuning kernel, jaringan, MTU/MSS dan rollback](dokumentasi/tuning-kernel-network.md)

Setiap akun punya batas sesi bersamaan `max_sessions` 1–3 (default 3). Backend menegakkannya setiap 5 detik: sesi IKE terbaru di atas batas dihentikan berdasarkan ID numerik, sesi tertua tetap hidup, tercatat di journald dan audit. Lihat [REST API: batas sesi](dokumentasi/rest-api.md#batas-sesi-bersamaan-max_sessions).

Pool /24 dipilih sekali dari `172.31.201..250.0/24` lalu disimpan di environment; reinstall mempertahankan pool, lease, DB, PKI dan API key. Tuning tidak memasang OpenVPN/WireGuard; preset kedua engine masih nonaktif.

Source di `src/`. Bangun ulang script setelah perubahan: `python3 build-installer.py`. Pengujian: buat venv, pasang `src/requirements.txt pytest httpx`, lalu `PYTHONPATH=src python -m pytest tests -q`.
