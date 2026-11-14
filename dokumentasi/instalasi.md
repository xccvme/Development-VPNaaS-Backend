# Instalasi dan operasi

Debian 13, root, akses apt/PyPI dan IPv4 publik. Buka UDP500/4500 pada firewall platform; ESP protocol50 bila tanpa NAT-T. Jangan membuka port8000 ke publik.

`bash install.sh` membuat CA/server certificate baru sesuai IP publik aktual, venv (tanpa melanggar PEP668), SQLite kosong, key acak, unit `vpnaas-api` dan timer `vpnaas-reconcile`. Nilai di awal script bisa diedit atau memakai env: `PUBLIC_IP`, `PUBLIC_IF`, `LAN_CIDR`, `LAN_IF`, `LAN_IP`, `FULL_DNS`. Nilai kosong mendeteksi/menjaga konfigurasi lama. DNS default 1.1.1.1,8.8.8.8. Nilai LAN menentukan default form/API, bukan pin interface pada mode route-auto.

Path:
- aplikasi/venv: `/opt/vpnaas/backend`
- database: `/var/lib/vpnaas/data.sqlite3`
- API key: `/etc/vpnaas/api.key`, root0600; UI satu VM membaca file ini, tidak perlu menyalin key
- konfigurasi nonsecret: `/etc/vpnaas/backend.env`, root0600
- CA private: `/var/lib/vpnaas/ca-key.pem`
- CA publik: `/etc/swanctl/x509ca/ca.pem`
- server cert/key: `/etc/swanctl/x509/server.pem`, `/etc/swanctl/private/server-key.pem`

Rerun menjaga DB, API key dan seluruh PKI. PKI tidak lengkap menghentikan installer; pulihkan backup, jangan menghapus key secara acak. Perubahan IP publik memerlukan sertifikat baru oleh operator; perubahan NIC privat tidak memerlukan reinstall.

`systemctl status vpnaas-api strongswan vpnaas-reconcile.timer`; `journalctl -u vpnaas-api -u vpnaas-reconcile`; `swanctl --list-sas`; `nft list table inet vpnaas`. Service Restart=always, request access log mati, stdout/stderr ke journald. Root diperlukan karena kontrol IPsec/nft. Ini single-gateway PoC, belum isolasi multi-tenant/RBAC/HA. Backup DB dan PKI/key via saluran terenkripsi, jangan commit.

Installer tidak flush nft ruleset, tidak mengubah INPUT/OUTPUT/SSH atau konfigurasi DHCP/QGA. Own forwarding chain policy drop dapat berpengaruh pada forwarding lain; pakai VM khusus gateway. Jangan menaruh konfigurasi swanctl tak terkait di VM ini: --load-all --clear memuat ulang credentials/pools global.

Uninstall manual hanya setelah backup: stop/disable unit dan timer milik VPNaaS, hapus own table `inet vpnaas`, own snippet `conf.d/vpnaas.conf` dan unit/sysctl milik VPNaaS. Jangan flush table lain. Evaluasi forwarding sebelum menonaktifkannya.
