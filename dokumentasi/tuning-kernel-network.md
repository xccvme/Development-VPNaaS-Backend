# Tuning kernel dan jaringan Debian 13

Installer hanya menjalankan engine IPsec/IKEv2 strongSwan. **OpenVPN dan WireGuard tidak diinstal**, tidak dibuat layanan atau interface-nya. Modul kernel `wireguard` boleh tersedia/dimuat untuk kesiapan; itu bukan tunnel siap pakai. Forwarding IPv6 juga bukan dukungan VPN IPv6: API, selector dan ACL VPN saat ini IPv4.

## Lokasi dan nilai

Sumber implementasi: `src/tuning.py`, pemanggilan dan parameter awal di `install.template.sh`. Hasil yang benar-benar berhasil diterapkan ditulis ke `/etc/sysctl.d/99-vpn-tuning.conf`; kegagalan/opsi kernel tidak tersedia dicatat ke output installer. Jangan menganggap semua kernel Debian 13 identik.

| Parameter | Default | Alasan |
|---|---|---|
| IPv4 ip_forward; IPv6 all/default forwarding | 1 | Kesiapan forwarding |
| IPv4 all/default rp_filter | 2 | Loose reverse-path check untuk routing VPN/asimetris |
| IPv4 all/default accept_redirects/send_redirects; IPv6 all/default accept_redirects | 0 | Tidak mengikuti/mengirim redirect |
| IPv6 all/default dan interface yang sudah ada accept_ra | 2 | Tetap belajar RA/default route walau forwarding hidup; tidak mematikan DHCP/QGA |
| rmem_max/wmem_max | 16777216 | Batas buffer 16 MiB, bukan alokasi tetap setiap socket |
| rmem_default/wmem_default | 1048576 | Default buffer 1 MiB |
| optmem_max | 65536 | Batas memori tambahan socket |
| netdev_max_backlog | 16384 | Batas antrean masuk |
| tcp_rmem | 4096 87380 16777216 | Minimum/default/maksimum TCP receive |
| tcp_wmem | 4096 65536 16777216 | Minimum/default/maksimum TCP send |
| tcp_mtu_probing; ip_no_pmtu_disc | 1; 0 | Probing saat masalah PMTU; PMTUD tetap aktif |
| nf_conntrack_max | 262144 | Batas entry, bukan jaminan kapasitas serentak |
| fs.file-max | 2097152 | Batas file global, bukan reservasi memori |
| default_qdisc; tcp_congestion_control | fq; bbr bila tersedia | Default koneksi/queue baru; tidak mengganti qdisc uplink aktif secara paksa |

Penulisan conntrack yang benar adalah `net.netfilter.nf_conntrack_max=262144`. Pada VM RAM sekitar 1 GiB, awasi `free -m`, slab conntrack dan socket memory: batas tinggi bukan janji mampu menangani 262144 sesi atau throughput tertentu. BBR mengontrol **TCP**, tidak mempercepat UDP outer IPsec/WireGuard/OpenVPN secara langsung.

`LimitNOFILE=65536` diterapkan pada unit API dan drop-in strongSwan. Drop-in daemon yang sudah berjalan efektif pada restart daemon berikutnya; installer tidak restart strongSwan hanya untuk mengganti limit agar sesi yang tidak perlu dicabut tetap aman.

Parameter buffer, backlog, TCP dan conntrack dapat diubah pada blok awal installer atau melalui `sudo env TUNE_NET_CORE_RMEM_MAX=8388608 bash install.sh`. Untuk parameter lainnya, pola override adalah `TUNE_` ditambah nama sysctl huruf besar dengan titik/dash menjadi underscore. Nilai numerik saja (daftar buffer dipisah spasi). Nilai yang diterapkan disimpan pada file sysctl sehingga tetap berlaku setelah boot.

## Modul dan offload

Installer mencoba `modprobe` untuk `tun wireguard af_key ah4 esp4 ipcomp xfrm4_tunnel xfrm_user nf_conntrack tcp_bbr sch_fq`. Hanya modul yang berhasil dimuat/tersedia disimpan di `/etc/modules-load.d/vpnaas.conf`. Baca log untuk `UNAVAILABLE`, `UNSUPPORTED/FAILED`; opsi yang gagal tidak ditulis seolah sudah aktif.

`vpnaas-offload.timer` menjalankan oneshot setiap sekitar 30 detik. Interface publik dipilih dari default route metric terendah saat itu, bukan nama NIC lama. Dengan `ethtool -k`, hanya fitur yang dapat diubah dicoba: GRO off, LRO off, `tx-udp_tnl-segmentation` off. Fitur absent atau `[fixed]` dicatat, bukan dianggap berhasil diubah. Ini mengikuti NIC publik yang terlambat muncul/berubah. Tidak ada perubahan alamat, route, DHCP, QGA atau MTU fisik. Menonaktifkan offload dapat menaikkan CPU dan menurunkan throughput; ukur beban nyata sebelum memakai default ini pada mesin besar.

## MTU, enkapsulasi dan MSS

**Jangan menurunkan MTU uplink fisik menjadi 1360.** Pada OpenStack, tenant MTU yang dilaporkan ke guest biasanya sudah memperhitungkan overhead VXLAN. VXLAN umum memakan sekitar 50 byte pada underlay IPv4 atau 70 byte pada IPv6 (tanpa opsi tambahan). Jangan mengurangi overhead VXLAN dua kali dari MTU guest. Periksa MTU interface, route dan konfigurasi provider; angka 9000 pada suatu NIC tidak menjamin PMTU internet 9000.

IPsec menambah header outer IP, ESP, IV, padding, integrity/tag, serta UDP 8 byte jika NAT-T. Total tergantung mode, cipher, padding dan keluarga IP; tidak ada satu angka overhead universal. nftables milik aplikasi memasang chain forward priority mangle untuk TCP SYN kedua arah, hanya untuk VIP VPN dan flow IPsec (`meta ipsec` masuk / `rt ipsec` keluar). MSS **hanya diturunkan bila di atas 1300**, tidak menaikkan MSS kecil. Ini cap konservatif, bukan bukti optimum universal; tidak mengubah paket UDP dan tidak menggantikan diagnosis PMTU.

`/etc/vpnaas/future-vpn-presets.json` menyimpan preset **nonaktif**: WireGuard MTU 1360, OpenVPN tun-mtu 1360 dan mssfix 1320. Integrator berikutnya harus menguji transport/versi dan mengimplementasikan engine dahulu. `mssfix` OpenVPN berhubungan dengan batas ukuran paket tunnel dan semantiknya bergantung versi/opsi, bukan selalu TCP MSS tepat 1320.

## Verifikasi

```bash
cat /etc/sysctl.d/99-vpn-tuning.conf
sysctl net.ipv4.ip_forward net.ipv6.conf.all.forwarding net.ipv6.conf.default.accept_ra
sysctl net.core.rmem_max net.ipv4.tcp_congestion_control net.netfilter.nf_conntrack_max
cat /etc/modules-load.d/vpnaas.conf
systemctl status vpnaas-offload.timer vpnaas-reconcile.timer
journalctl -u vpnaas-offload.service --since today
ip -4 route; ip -6 route; ip link
ethtool -k NAMA_NIC_PUBLIK
nft -c -f /opt/vpnaas/firewall.nft
nft list table inet vpnaas
systemctl show vpnaas-api strongswan -p LimitNOFILE
```

Route private/ACL tetap dikelola `vpnaas-reconcile.timer` sekitar 5 detik, terpisah dari timer offload. Hanya table `inet vpnaas` diganti atomik; tidak ada flush global nftables, sehingga Docker dan akses SSH tetap dipertahankan. Uji konektivitas LAN dari klien dengan VIP dan counter CHILD, bukan sekadar status engine.

## Rollback

Simpan akses console provider sebelum mengubah jaringan. Backup sebelum install berada di `/var/backups/vpnaas/<timestamp>/`, root-only, termasuk env, DB konsisten SQLite, konfigurasi swanctl, PKI dan file tuning sebelumnya bila ada. Hentikan timer offload jika hendak membalikkan offload, lalu `ethtool -K NIC gro on` hanya jika memang nilai awalnya on. Pulihkan nilai sysctl awal dari catatan operator/backup dan terapkan satu per satu; menghapus file tidak otomatis membalik nilai live. Jangan `sysctl --system` tanpa meninjau file milik layanan lain. Pulihkan modules-load bila diperlukan; jangan unload modul IPsec aktif. Pulihkan DB/env/konfigurasi secara satu set dengan API dan reconcile berhenti; restart API setelah memastikan pool dan lease konsisten. Modul yang dimuat tidak berarti harus di-unload saat rollback.

Pemilihan pool dan migrasi VIP dibahas terpisah di [pool VIP](pool-vip.md).
