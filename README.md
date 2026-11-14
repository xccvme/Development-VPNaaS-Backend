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
- [API dan fitur](dokumentasi/api.md)
- [NIC privat dipasang belakangan](dokumentasi/jaringan.md)
- [Panduan Windows](dokumentasi/windows.md)

Source di `src/`. Bangun ulang script setelah perubahan: `python3 build-installer.py`. Pengujian: buat venv, pasang `src/requirements.txt pytest httpx`, lalu `PYTHONPATH=src python -m pytest tests -q`.
