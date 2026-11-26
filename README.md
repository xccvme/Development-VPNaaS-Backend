# VPNaaS Backend (Enterprise IPsec/IKEv2 — FIPS Aligned)

Backend REST API untuk layanan **Enterprise VPN as a Service (IPsec/IKEv2)** berbasis **strongSwan 6 + nftables + SQLite + FastAPI** untuk **Debian 13**.

- **Default Split-Tunnel:** Trafik internet client/site tidak dilewatkan ke server VPN (kecuali akun C2S yang eksplisit disetel `traffic_mode: full`).
- **Native REST API (`0.0.0.0:8000`):** Endpoint dan request body yang dipakai oleh UI Development maupun Customer Portal adalah **100% sama** menggunakan header `X-API-Key` dari `/etc/vpnaas/api.key`. Pembatasan akses port `8000` dilakukan di **Cloud/OpenStack Security Group** (hanya izinkan IP server Customer Portal).
- **Siap Golden Image / Snapshot VM:** Dilengkapi `vpnaas-bootstrap.service` yang otomatis mendeteksi VM baru hasil clone snapshot dan membuat ulang `api.key`, Root CA, Server Cert, VIP Pool, serta konfigurasi jaringan/routing VM baru.

---

## 1. Instalasi Baru (Fresh Install)

Jalankan pada VM Debian 13 yang sudah memiliki akses internet & IPv4 publik (atau Floating IP):

```bash
sudo apt-get update && sudo apt-get upgrade -y
sudo apt-get install -y ca-certificates git
git clone https://github.com/xccvme/Development-VPNaaS-Backend.git
cd Development-VPNaaS-Backend
chmod +x install.sh
sudo bash install.sh
```

> Jika login langsung sebagai `root`, hilangkan `sudo`.

### Aturan Security Group (Cloud / OpenStack)
- **UDP 500 & UDP 4500:** Buka ke `0.0.0.0/0` (atau IP peer S2S/C2S) untuk tunnel IPsec/IKEv2 NAT-T.
- **TCP 8000 (REST API):** Buka **hanya ke IP server Customer Portal** (dan/atau server manajemen). Di dalam VM, backend mendengarkan di `0.0.0.0:8000` (bisa diubah via `API_HOST=127.0.0.1` bila hanya dipakai lokal).
- **API Key:** tersimpan root-only di `/etc/vpnaas/api.key` (kirim lewat header `X-API-Key: <isi-file>`).

---

## 2. Cara Update Backend (Data & Konfigurasi Tetap Aman)

Gunakan langkah ini saat ada pembaruan kode di GitHub dan ingin **mempertahankan seluruh data** (SQLite DB, Site S2S, Akun C2S, PKI Root CA, VIP Pool, dan API Key):

```bash
cd ~/Development-VPNaaS-Backend
git fetch origin
git reset --hard origin/main
chmod +x install.sh
sudo bash install.sh
```

Verifikasi layanan setelah update:
```bash
sudo systemctl status vpnaas-api strongswan --no-pager
curl -s -H "X-API-Key: $(sudo cat /etc/vpnaas/api.key)" http://127.0.0.1:8000/api/ready
```

> Installer otomatis membuat backup ke `/var/backups/vpnaas/<timestamp>` sebelum menimpa source, serta mempertahankan DB, PKI, pool, dan `/etc/vpnaas/api.key`.

---

## 3. Cara Install Ulang Bersih / Reset Semua Data (Clean Reinstall)

Gunakan langkah ini jika ingin **menghapus semua data lama** (reset DB, PKI, API Key, env) dan mulai dari nol:

```bash
# 1. Hentikan seluruh layanan VPNaaS
sudo systemctl stop vpnaas-reconcile.timer vpnaas-offload.timer vpnaas-api.service strongswan.service 2>/dev/null || true

# 2. Hapus state, PKI, DB, konfigurasi, dan backup lama
sudo rm -rf /var/lib/vpnaas /etc/vpnaas /var/backups/vpnaas /opt/vpnaas
sudo rm -rf /etc/swanctl/conf.d/vpnaas.conf /etc/swanctl/x509ca/ca.pem /etc/swanctl/x509/server.pem /etc/swanctl/private/server-key.pem /etc/swanctl/x509crl/ca.crl
sudo nft delete table inet vpnaas 2>/dev/null || true

# 3. Ambil source terbaru & jalankan installer
cd ~
rm -rf Development-VPNaaS-Backend
git clone https://github.com/xccvme/Development-VPNaaS-Backend.git
cd Development-VPNaaS-Backend
chmod +x install.sh
sudo bash install.sh
```

> Jika UI berjalan di VM yang sama, jalankan ulang UI (`sudo docker compose up -d --force-recreate`) agar membaca `/etc/vpnaas/api.key` yang baru dibuat.

---

## 4. Membuat Preconfigured Golden Image (VM Snapshot)

Untuk membuat template image VM Debian 13 agar setiap VM baru yang dibuat dari snapshot otomatis menyesuaikan IP publik, VPC, PKI, VIP pool, dan API key unik:

**Cara A — Install langsung dalam mode Golden Image (tidak butuh IP publik di VM builder):**
```bash
git clone https://github.com/xccvme/Development-VPNaaS-Backend.git
cd Development-VPNaaS-Backend
sudo bash install.sh --prepare-image
sudo cloud-init clean --logs   # opsional, direkomendasikan di OpenStack
sudo poweroff
```

**Cara B — Menjadikan VM yang sudah terinstall sebagai Golden Image:**
```bash
sudo vpnaas-prepare-image
sudo cloud-init clean --logs   # opsional
sudo poweroff
```

Setelah poweroff, buat **Snapshot / Image** di OpenStack/Hypervisor. Saat VM baru dijalankan dari image tersebut, `vpnaas-bootstrap.service` otomatis membuat identitas & konfigurasi baru sebelum strongSwan dan API menyala.

---

## 5. Pengembangan & Pengujian Lokal

- Source berada di `src/`.
- Bangun ulang installer single-file setelah mengubah `src/` atau `install.template.sh`:
  ```bash
  python3 build-installer.py
  ```
- Jalankan unit test:
  ```bash
  PYTHONPATH=src python3 -m pytest tests -q
  ```

## Dokumentasi Tambahan

- [Instalasi, variabel opsional, dan operasi](dokumentasi/instalasi.md)
- [Panduan REST API lengkap](dokumentasi/rest-api.md)
- [NIC privat dipasang belakangan](dokumentasi/jaringan.md)
- [Site-to-Site & routing](dokumentasi/site-to-site.md)
- [Pool VIP acak per server](dokumentasi/pool-vip.md)
- [Tuning kernel, jaringan, MTU/MSS](dokumentasi/tuning-kernel-network.md)
