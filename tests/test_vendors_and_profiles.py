"""Multi-vendor S2S config generators (MikroTik, FortiGate, Cisco, strongSwan) and C2S profiles (Apple, Android, Windows)."""
import json
import plistlib
from test_api import TestClient
from app import app

H = {'X-API-Key': 'test-key'}


def client():
    return TestClient(app, headers=H)


def test_multivendor_site_and_hub_configs():
    c = client()
    site = c.post('/api/sites', json={
        'name': 'cabang-surabaya',
        'subnets': '192.168.70.0/24',
        'psk': 'super-secret-sby-key-1234',
    }).json()
    hub = c.post('/api/connections', json={
        'name': 'hub-vendor',
        'topology': 'hub',
        'site_a': {'subnets': '10.1.0.0/24', 'psk': 'hub-vendor-psk-a-1234'},
        'site_b': {'subnets': '10.2.0.0/24', 'psk': 'hub-vendor-psk-b-1234'},
    }).json()
    try:
        mt = c.get(f"/api/sites/{site['id']}/config?vendor=mikrotik")
        assert mt.status_code == 200 and 'MikroTik-' in mt.headers['content-disposition']
        assert '/ip ipsec peer add' in mt.text and 'exchange-mode=ike2' in mt.text and 'super-secret-sby-key-1234' in mt.text
        assert 'src-address=192.168.70.0/24' in mt.text

        fg = c.get(f"/api/sites/{site['id']}/config?vendor=fortigate")
        assert fg.status_code == 200 and 'FortiGate-' in fg.headers['content-disposition']
        assert 'config vpn ipsec phase1-interface' in fg.text and 'set ike-version 2' in fg.text and 'set dhgrp 14' in fg.text

        cs = c.get(f"/api/sites/{site['id']}/config?vendor=cisco")
        assert cs.status_code == 200 and 'Cisco-IOSXE-' in cs.headers['content-disposition']
        assert 'crypto ikev2 proposal' in cs.text and 'group 14' in cs.text and 'esp-aes 256 esp-sha256-hmac' in cs.text

        sc = c.get(f"/api/sites/{site['id']}/config?vendor=swanctl")
        assert sc.status_code == 200 and 'encap = yes' in sc.text

        sh = c.get(f"/api/sites/{site['id']}/config?vendor=script")
        assert sh.status_code == 200 and sh.text.startswith('#!/usr/bin/env bash\n') and 'rt ipsec exists' in sh.text

        # Legacy Hub endpoint also supports new vendor formats!
        hub_mt = c.get(f"/api/connections/{hub['id']}/sites/a/config?format=mikrotik")
        assert hub_mt.status_code == 200 and 'src-address=10.1.0.0/24 dst-address=10.2.0.0/24' in hub_mt.text
        hub_fg = c.get(f"/api/connections/{hub['id']}/sites/b/config?format=fortigate")
        assert hub_fg.status_code == 200 and 'hub-vendor-psk-b-1234' in hub_fg.text
    finally:
        c.delete(f"/api/sites/{site['id']}")
        c.delete(f"/api/connections/{hub['id']}")


def test_multiplatform_c2s_profiles(tmp_path, monkeypatch):
    monkeypatch.setenv('VPNAAS_SWANCTL_DIR', str(tmp_path / 'swanctl'))
    monkeypatch.setenv('VPNAAS_CA_KEY', str(tmp_path / 'ca-key.pem'))
    c = client()
    c.post('/api/pki/server/rotate', json={})
    u = c.post('/api/users', json={
        'username': 'remote-worker',
        'password': 'worker-secret-password',
        'allowed_cidrs': ['10.10.7.0/24'],
        'traffic_mode': 'split',
    }).json()
    try:
        # 1. Apple .mobileconfig -> valid XML plist with CA + IKEv2 + split route
        mc = c.get(f"/api/users/{u['id']}/profile?format=mobileconfig")
        assert mc.status_code == 200 and 'no-store' in mc.headers['cache-control']
        assert '.mobileconfig' in mc.headers['content-disposition']
        plist = plistlib.loads(mc.content)
        types = [p['PayloadType'] for p in plist['PayloadContent']]
        assert 'com.apple.security.root' in types and 'com.apple.vpn.managed' in types
        vpn_p = next(p for p in plist['PayloadContent'] if p['PayloadType'] == 'com.apple.vpn.managed')
        assert vpn_p['VPNType'] == 'IKEv2' and vpn_p['IKEv2']['AuthName'] == 'remote-worker'
        assert vpn_p['IPv4']['IncludedRoutes'][0]['DestinationAddress'] == '10.10.7.0'

        # 2. Android strongSwan .sswan -> valid JSON with cert & split subnets
        ss = c.get(f"/api/users/{u['id']}/profile?format=sswan")
        assert ss.status_code == 200 and '.sswan' in ss.headers['content-disposition']
        doc = json.loads(ss.text)
        assert doc['type'] == 'ikev2-eap' and doc['local']['eap_id'] == 'remote-worker'
        assert doc['split-tunneling']['subnets'] == ['10.10.7.0/24'] and 'cert' in doc['remote']

        # 3. Windows .ps1 -> PowerShell setup without leaking plaintext password
        win = c.get(f"/api/users/{u['id']}/profile?format=windows")
        assert win.status_code == 200 and '.ps1' in win.headers['content-disposition']
        assert 'Add-VpnConnection' in win.text and 'DHGroup Group14' in win.text
        assert 'worker-secret-password' not in win.text
    finally:
        c.delete(f"/api/users/{u['id']}")
