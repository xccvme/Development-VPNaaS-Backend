# Hasil test2 — 14 November 2026

Debian13.6, public ens3 38.47.85.19/24, default38.47.85.254. strongSwan6.0.1. VM awal tanpa private NIC. Tidak mengakses/mengubah PoC lama.

- Installer standalone nyata sukses, loopback127.0.0.1:8000; strongswan/vpnaas-api/reconcile.timer active.
- Rerun final: SHA256 API key, CA private/public, server private/public dan SQLite semuanya OK identik sebelum/sesudah.
- Health auth, split/full account CRUD, profile identity, secret redaction, password/disable/enable revoke, S2S dan policy CRUD benar-benar menerapkan swanctl/nft. Objek sementara dibersihkan.
- EAP dengan IDi172.31.254.2 berbeda dari username berhasil lewat isolated namespace + daemon/VICI. IKE ESTABLISHED, CHILD INSTALLED, selector0/0, DNS DNS CPRP. Runtime API Active.
- Ping1.1.1.1:3/3. HTTPS ifconfig.me:38.47.85.19. Counter IPsec meningkat. Disable akun mencabut SA, runtime Down. Namespace/daemon/credential probe dibersihkan. Probe berjalan pada VM gateway, bukan bukti jalur UDP dari internet eksternal.
- Late NIC: akun subnet10.44.0.0/24 tanpa route → drop/not-ready. Attach dummy latevpn0 + IP10.44.0.2/24 → timer membuat oif-qualified grant+masquerade/ready. Ganti IP ke.3 tetap tanpa fixed SNAT. Detach → stale grant hilang, drop/not-ready. SSH/API tetap tersedia. Dummy tidak membuktikan traffic LAN fisik; NIC privat aktual belum dipasang.
- Suite lokal32 passed. Script live reproduksi di tests/live_acceptance.py, live_tunnel.py, live_late_nic.py (root gateway; jalankan terpisah). live_acceptance/profile assertion disiapkan khusus test2. Source distribution bukan file runtime test.

Awal paket extra-plugins belum memuat EAP-MSCHAPv2; final installer menyertakan extauth + standard crypto plugins. Warning agent optional saat swanctl tidak memblokir negosiasi. DNS resolver plugin probe dimatikan agar tidak mengubah resolver host; DNS push terlihat, bukan bukti penerapan DNS Windows. Windows, LAN produksi dan S2S actual peer belum diuji end-to-end.
