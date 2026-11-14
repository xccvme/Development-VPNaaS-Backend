# VPNaaS backend

API IKEv2 strongSwan 6 untuk Debian 13. Jalankan sebagai root:

```sh
bash install.sh
```

Installer sudah memuat source aplikasi; tidak perlu clone repo, Docker, atau input interaktif. Paket Debian dan Python tetap diunduh dari internet. API hanya `127.0.0.1:8000`. UI satu VM membaca key root-only `/etc/vpnaas/api.key`.

- [Instalasi dan operasi](dokumentasi/instalasi.md)
- [API dan fitur](dokumentasi/api.md)
- [NIC privat dipasang belakangan](dokumentasi/jaringan.md)
- [Panduan Windows](dokumentasi/windows.md)
- [Hasil pengujian test2](dokumentasi/pengujian.md)

Source di `src/`. Bangun ulang script setelah perubahan: `python3 build-installer.py`. Pengujian: buat venv, pasang `src/requirements.txt pytest httpx`, lalu `PYTHONPATH=src python -m pytest tests -q`.
