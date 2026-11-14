# Public NIC dulu, private NIC belakangan

VM boleh dibuat hanya dengan public NIC. DHCP/QGA dikelola platform, bukan installer ini. Tanpa private NIC, default izin placeholder `192.0.2.0/24`; akun tetap bisa dibuat dengan allowed_cidrs subnet yang nantinya dipasang.

`VPNAAS_ROUTE_AUTO=1` aktif dari installer. Timer tiap5 detik membaca route IPv4 main kernel, memilih default interface untuk internet, dan mencari route spesifik yang mencakup seluruh CIDR izin lewat NIC nonpublik. Route default saja tidak dianggap akses LAN. Route blackhole, loopback, publik, atau route lebih spesifik yang tidak aman membuat grant ditolak konservatif.

Sebelum route privat ada: paket grant di-drop, `/api/status.network.private_routes` menampilkan ready=false/interface=null. Setelah NIC mendapat IP/route, timer mengubah own nft: grant terikat oifname dan NAT `masquerade`, bukan IP LAN statis. Pergantian IP otomatis mengikuti NAT. Saat detach grant/NAT hilang, paket ditolak kembali. Sampai timer berikutnya (sekitar5–6 detik), aturan lama tetap oif-qualified sehingga tidak pindah ke default publik. Rekonsiliasi tidak reload swanctl, tidak revoke SA; hanya batch nft own-table yang lolos --check, dengan flock yang sama dengan mutation API. Bila render tak berubah tidak ada nft apply.

Selector split tetap allowed_cidrs, tidak bergantung NIC. Mode full memakai selector0/0, internet masquerade lewat public default aktual, MSS1360, DNS push, blok private/reserved di luar LAN grants. ACL pool diproses sebelum ct established agar flow lama tidak lolos setelah detach. Mode full hanya IPv4: bukan IPv6 tunnel/kill-switch. Route policy multipath/table non-main belum didukung; gunakan route main eksplisit.

Pastikan subnet yang diizinkan benar-benar memiliki route melalui NIC privat pada gateway. Uji akses host LAN dan return route secara terpisah; NIC terdeteksi tidak otomatis membuktikan konektivitas seluruh LAN.
