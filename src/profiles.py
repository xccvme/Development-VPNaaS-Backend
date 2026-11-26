"""Multi-platform C2S IKEv2 client profile generators.

Supports:
- json:         Standard JSON profile (backward compatible with existing clients/UI)
- mobileconfig: Apple Configuration Profile XML (.mobileconfig) for macOS / iOS / iPadOS
- sswan:        strongSwan Android VPN Client JSON profile (.sswan)
- windows:      Windows Native IKEv2 PowerShell setup script (.ps1)
"""
import base64
import ipaddress
import json
import os
import re
import uuid
import xml.sax.saxutils as xmlutil


PROFILE_FORMATS = ('json', 'mobileconfig', 'sswan', 'windows')


def _safe_filename(name: str, fallback: str = 'user') -> str:
    cleaned = re.sub(r'[^A-Za-z0-9_.-]+', '_', str(name)).strip('._')
    if not cleaned or cleaned.upper() in ('CON', 'PRN', 'AUX', 'NUL', *(f'COM{i}' for i in range(1, 10)), *(f'LPT{i}' for i in range(1, 10))):
        cleaned = '_' + (cleaned or fallback)
    return cleaned


def _pem_to_der_b64(pem: str) -> str:
    lines = [line.strip() for line in pem.splitlines() if line.strip() and not line.strip().startswith('-----')]
    return ''.join(lines)


def build_json_profile(user, ca_pem: str, eff_cidrs: list, cert_row=None) -> dict:
    from vpn import vip, full_dns, public_ip
    mode = user.get('traffic_mode', 'split')
    srv = os.environ.get('VPNAAS_PUBLIC_IP') or public_ip()
    auth_method = user.get('auth_method', 'eap-mschapv2')
    data = {
        'username': user['username'],
        'password': user.get('password', ''),
        'auth_method': auth_method,
        'traffic_mode': mode,
        'server': srv,
        'server_id': srv,
        'virtual_ip': vip(user),
        'allowed_cidrs': eff_cidrs,
        'ca_certificate': ca_pem,
    }
    if mode == 'full':
        data['dns'] = full_dns()
    if cert_row and auth_method in ('pubkey', 'eap-tls'):
        data['client_certificate'] = cert_row.get('cert_pem', '')
        data['client_serial'] = cert_row.get('serial', '')
        data['client_id'] = cert_row.get('san', user['username'])
    return data


def build_mobileconfig(profile: dict, p12_bytes: bytes = None) -> tuple:
    """Generate Apple macOS/iOS/iPadOS .mobileconfig XML profile for native IKEv2."""
    esc = xmlutil.escape
    user = profile['username']
    server = profile['server']
    server_id = profile['server_id']
    mode = profile['traffic_mode']
    auth_method = profile.get('auth_method', 'eap-mschapv2')

    root_uuid = str(uuid.uuid5(uuid.NAMESPACE_DNS, f'vpnaas.profile.{server}.{user}'))
    vpn_uuid = str(uuid.uuid5(uuid.NAMESPACE_DNS, f'vpnaas.vpn.{server}.{user}'))
    ca_uuid = str(uuid.uuid5(uuid.NAMESPACE_DNS, f'vpnaas.ca.{server}'))
    p12_uuid = str(uuid.uuid5(uuid.NAMESPACE_DNS, f'vpnaas.p12.{server}.{user}'))

    payloads = []
    ca_b64 = _pem_to_der_b64(profile.get('ca_certificate', ''))
    if ca_b64:
        payloads.append(f'''    <dict>
      <key>PayloadCertificateFileName</key>
      <string>vpnaas-ca.cer</string>
      <key>PayloadContent</key>
      <data>{ca_b64}</data>
      <key>PayloadDisplayName</key>
      <string>VPNaaS Root CA</string>
      <key>PayloadIdentifier</key>
      <string>id.dcloud.vpnaas.ca.{esc(_safe_filename(server))}</string>
      <key>PayloadType</key>
      <string>com.apple.security.root</string>
      <key>PayloadUUID</key>
      <string>{ca_uuid}</string>
      <key>PayloadVersion</key>
      <integer>1</integer>
    </dict>''')

    if p12_bytes and auth_method in ('pubkey', 'eap-tls'):
        p12_b64 = base64.b64encode(p12_bytes).decode('ascii')
        payloads.append(f'''    <dict>
      <key>PayloadCertificateFileName</key>
      <string>{esc(_safe_filename(user))}.p12</string>
      <key>PayloadContent</key>
      <data>{p12_b64}</data>
      <key>PayloadDisplayName</key>
      <string>VPNaaS Client Cert ({esc(user)})</string>
      <key>PayloadIdentifier</key>
      <string>id.dcloud.vpnaas.cert.{esc(_safe_filename(user))}</string>
      <key>PayloadType</key>
      <string>com.apple.security.pkcs12</string>
      <key>PayloadUUID</key>
      <string>{p12_uuid}</string>
      <key>PayloadVersion</key>
      <integer>1</integer>
    </dict>''')

    if auth_method == 'pubkey':
        auth_xml = f'''        <key>AuthenticationMethod</key>
        <string>Certificate</string>
        <key>PayloadCertificateUUID</key>
        <string>{p12_uuid}</string>
        <key>LocalIdentifier</key>
        <string>{esc(profile.get("client_id", user))}</string>'''
    elif auth_method == 'eap-tls':
        auth_xml = f'''        <key>AuthenticationMethod</key>
        <string>Certificate</string>
        <key>ExtendedAuthEnabled</key>
        <integer>1</integer>
        <key>PayloadCertificateUUID</key>
        <string>{p12_uuid}</string>
        <key>AuthName</key>
        <string>{esc(user)}</string>'''
    else:
        auth_xml = f'''        <key>AuthenticationMethod</key>
        <string>None</string>
        <key>ExtendedAuthEnabled</key>
        <integer>1</integer>
        <key>AuthName</key>
        <string>{esc(user)}</string>'''

    routes_xml = ''
    if mode != 'full':
        entries = []
        for c in profile.get('allowed_cidrs', []):
            net = ipaddress.IPv4Network(c)
            entries.append(f'''          <dict>
            <key>DestinationAddress</key>
            <string>{net.network_address}</string>
            <key>SubnetMask</key>
            <string>{net.netmask}</string>
          </dict>''')
        routes_xml = f'''      <key>IPv4</key>
      <dict>
        <key>OverridePrimary</key>
        <integer>0</integer>
        <key>IncludedRoutes</key>
        <array>
{chr(10).join(entries)}
        </array>
      </dict>'''
    else:
        dns_items = ''.join(f'<string>{esc(d)}</string>' for d in profile.get('dns', []))
        routes_xml = f'''      <key>IPv4</key>
      <dict>
        <key>OverridePrimary</key>
        <integer>1</integer>
      </dict>
      <key>DNS</key>
      <dict>
        <key>ServerAddresses</key>
        <array>{dns_items}</array>
      </dict>'''

    payloads.append(f'''    <dict>
      <key>PayloadDisplayName</key>
      <string>VPNaaS ({esc(user)})</string>
      <key>PayloadIdentifier</key>
      <string>id.dcloud.vpnaas.vpn.{esc(_safe_filename(user))}</string>
      <key>PayloadType</key>
      <string>com.apple.vpn.managed</string>
      <key>PayloadUUID</key>
      <string>{vpn_uuid}</string>
      <key>PayloadVersion</key>
      <integer>1</integer>
      <key>UserDefinedName</key>
      <string>VPNaaS - {esc(user)}</string>
      <key>VPNType</key>
      <string>IKEv2</string>
      <key>IKEv2</key>
      <dict>
        <key>RemoteAddress</key>
        <string>{esc(server)}</string>
        <key>RemoteIdentifier</key>
        <string>{esc(server_id)}</string>
        <key>ServerCertificateCommonName</key>
        <string>{esc(server_id)}</string>
        <key>DeadPeerDetectionRate</key>
        <string>Medium</string>
        <key>DisableMOBIKE</key>
        <integer>0</integer>
        <key>IKESecurityAssociationParameters</key>
        <dict>
          <key>EncryptionAlgorithm</key>
          <string>AES-256</string>
          <key>IntegrityAlgorithm</key>
          <string>SHA2-256</string>
          <key>DiffieHellmanGroup</key>
          <integer>14</integer>
        </dict>
        <key>ChildSecurityAssociationParameters</key>
        <dict>
          <key>EncryptionAlgorithm</key>
          <string>AES-256</string>
          <key>IntegrityAlgorithm</key>
          <string>SHA2-256</string>
          <key>DiffieHellmanGroup</key>
          <integer>14</integer>
        </dict>
{auth_xml}
      </dict>
{routes_xml}
    </dict>''')

    xml = f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>PayloadContent</key>
  <array>
{chr(10).join(payloads)}
  </array>
  <key>PayloadDisplayName</key>
  <string>VPNaaS IKEv2 ({esc(user)})</string>
  <key>PayloadIdentifier</key>
  <string>id.dcloud.vpnaas.profile.{esc(_safe_filename(user))}</string>
  <key>PayloadOrganization</key>
  <string>DCloud VPNaaS</string>
  <key>PayloadRemovalDisallowed</key>
  <false/>
  <key>PayloadType</key>
  <string>Configuration</string>
  <key>PayloadUUID</key>
  <string>{root_uuid}</string>
  <key>PayloadVersion</key>
  <integer>1</integer>
</dict>
</plist>
'''
    fname = f'VPNaaS-{_safe_filename(user)}.mobileconfig'
    return xml, fname


def build_sswan(profile: dict, p12_bytes: bytes = None) -> tuple:
    """Generate Android strongSwan VPN Client (.sswan) JSON profile."""
    user = profile['username']
    server = profile['server']
    auth_method = profile.get('auth_method', 'eap-mschapv2')
    mode = profile['traffic_mode']

    sswan_type = {
        'eap-mschapv2': 'ikev2-eap',
        'pubkey': 'ikev2-cert',
        'eap-tls': 'ikev2-cert-eap',
    }.get(auth_method, 'ikev2-eap')

    doc = {
        'uuid': str(uuid.uuid5(uuid.NAMESPACE_DNS, f'vpnaas.sswan.{server}.{user}')),
        'name': f'VPNaaS - {user}',
        'type': sswan_type,
        'remote': {
            'addr': server,
            'id': profile['server_id'],
        },
        'local': {},
        'mtu': 1360,
        'ipv6-transport': False,
        'split-tunneling': {
            'block-ipv6': mode == 'full',
        },
    }
    ca_b64 = _pem_to_der_b64(profile.get('ca_certificate', ''))
    if ca_b64:
        doc['remote']['cert'] = ca_b64
    if auth_method == 'eap-mschapv2':
        doc['local']['eap_id'] = user
    else:
        doc['local']['id'] = profile.get('client_id', user)
        if p12_bytes:
            doc['local']['p12'] = base64.b64encode(p12_bytes).decode('ascii')
    if mode != 'full':
        doc['split-tunneling']['subnets'] = list(profile.get('allowed_cidrs', []))

    fname = f'VPNaaS-{_safe_filename(user)}.sswan'
    return json.dumps(doc, indent=2) + '\n', fname


def build_windows_ps1(profile: dict) -> tuple:
    """Generate Windows PowerShell native IKEv2 client setup script (never embeds password)."""
    user = profile['username']
    server = profile['server']
    mode = profile['traffic_mode']
    auth_method = profile.get('auth_method', 'eap-mschapv2')
    ca_pem = profile.get('ca_certificate', '').strip()
    cidrs = profile.get('allowed_cidrs', [])

    auth_flag = 'MachineCertificate' if auth_method == 'pubkey' else 'Eap'
    route_lines = []
    if mode != 'full':
        for c in cidrs:
            route_lines.append(f"Add-VpnConnectionRoute -ConnectionName $ConnName -DestinationPrefix '{c}' -ErrorAction SilentlyContinue")
    routes_block = '\n'.join(route_lines) if route_lines else '# Full-tunnel: semua trafik IPv4 lewat VPN'

    ps1 = f'''#Requires -RunAsAdministrator
# VPNaaS Windows Native IKEv2 Setup - {user}
# Jalankan di PowerShell (Run as Administrator). Password dimasukkan saat Connect.
$ErrorActionPreference = 'Stop'
$ConnName = '{user}'
$Server   = '{server}'

$CaPem = @'
{ca_pem}
'@
if ($CaPem.Trim().Length -gt 0) {{
    $TempCa = Join-Path $env:TEMP "vpnaas-ca-{_safe_filename(user)}.pem"
    [IO.File]::WriteAllText($TempCa, $CaPem, [Text.Encoding]::ASCII)
    certutil -addstore -f Root $TempCa | Out-Null
    Remove-Item $TempCa -Force -ErrorAction SilentlyContinue
}}

Remove-VpnConnection -Name $ConnName -Force -ErrorAction SilentlyContinue
Add-VpnConnection -Name $ConnName -ServerAddress $Server -TunnelType Ikev2 -AuthenticationMethod {auth_flag} -EncryptionLevel Required -Force
Set-VpnConnectionIPsecConfiguration -ConnectionName $ConnName `
    -AuthenticationTransformConstants SHA256128 `
    -CipherTransformConstants AES256 `
    -EncryptionMethod AES256 `
    -IntegrityCheckMethod SHA256 `
    -DHGroup Group14 `
    -PfsGroup None -Force
Set-VpnConnection -Name $ConnName -SplitTunneling ${str(mode != 'full')}
{routes_block}
Write-Host "Profil VPN '$ConnName' ($Server, mode={mode}, auth={auth_method}) siap digunakan."
'''
    fname = f'Setup-Client-{_safe_filename(user)}.ps1'
    return ps1, fname
