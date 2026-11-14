# Windows native IKEv2

Buat akun dari UI, pilih split/full, dan unduh JSON profil melalui admin. JSON sensitif. Server/CA/allowed_cidrs mengikuti profil, bukan IP contoh dokumen. UI dapat menyediakan .ps1 setup; jangan simpan password pada command history.

PowerShell Administrator, ekstrak CA publik dari profil lalu impor ke LocalMachine Root setelah verifikasi fingerprint dengan admin:

```powershell
$p = Get-Content .\profile.json -Raw | ConvertFrom-Json
[IO.File]::WriteAllText("$PWD\vpnaas-ca.pem", $p.ca_certificate, [Text.Encoding]::ASCII)
certutil -addstore -f Root .\vpnaas-ca.pem
Add-VpnConnection -Name 'VPNaaS' -ServerAddress $p.server -TunnelType Ikev2 -AuthenticationMethod Eap -EncryptionLevel Required -Force
Set-VpnConnectionIPsecConfiguration -ConnectionName 'VPNaaS' -AuthenticationTransformConstants SHA256128 -CipherTransformConstants AES256 -EncryptionMethod AES256 -IntegrityCheckMethod SHA256 -DHGroup Group14 -PfsGroup None -Force
Set-VpnConnection -Name 'VPNaaS' -SplitTunneling ($p.traffic_mode -ne 'full')
if ($p.traffic_mode -ne 'full') { foreach ($cidr in $p.allowed_cidrs) { Add-VpnConnectionRoute -ConnectionName 'VPNaaS' -DestinationPrefix $cidr } }
```

Security properties: EAP Microsoft Secured password (EAP-MSCHAP v2). Masukkan kredensial akun VPN di dialog Windows, bukan akun UI. Nama ConnectionName harus cocok nama profil aktual; profil all-users perlu parameter AllUserConnection. Saat mengganti mode: disconnect, hapus route split lama untuk full, terapkan setup lagi, reconnect.

Periksa `Get-VpnConnection -Name VPNaaS`, route IPv4, ping target LAN yang diizinkan dan benar-benar reachable. Full: `curl.exe -4 https://ifconfig.me` harus menunjukkan gateway. Windows belum dieksekusi pada test2; bukti Linux bukan bukti Windows. IPv6 dapat memakai koneksi lokal.

Timeout: periksa UDP500/4500 dan firewall platform. `Test-NetConnection -Port 500` menguji TCP, bukan IKE. Certificate error: trust LocalMachine, IP SAN, waktu, EKU. Proposal mismatch: Group14/AES256/SHA256, jangan melemahkan server ke DH1024/3DES. Connected tanpa LAN: cek status network ready, route, allowed_cidrs dan host tujuan. Jangan mematikan validasi sertifikat/firewall global.
