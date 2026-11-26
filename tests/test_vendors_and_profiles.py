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

        gn = c.get(f"/api/sites/{site['id']}/config?vendor=generic")
        assert gn.status_code == 200 and 'Enterprise-Config-' in gn.headers['content-disposition']
        assert '[GATEWAY_HUB]' in gn.text and '[PHASE1_IKEV2]' in gn.text and '[PHASE2_IPSEC_ESP]' in gn.text
        assert 'super-secret-sby-key-1234' in gn.text and '192.168.70.0/24' in gn.text

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

        # 4. Universal manual .conf guide & Root CA .crt / leaf .crt / .key downloads
        man = c.get(f"/api/users/{u['id']}/profile?format=manual")
        assert man.status_code == 200 and 'VPNaaS-Client-' in man.headers['content-disposition']
        assert '[GATEWAY_SERVER]' in man.text and 'remote-worker' in man.text and '10.10.7.0/24' in man.text
        assert 'worker-secret-password' not in man.text

        ca_crt = c.get('/api/pki/ca/cert?format=crt')
        assert ca_crt.status_code == 200 and 'vpnaas-ca.crt' in ca_crt.headers['content-disposition']
        assert 'BEGIN CERTIFICATE' in ca_crt.text

        cert = c.post('/api/pki/certs', json={'name': 'sw-core', 'target_type': 'site'}).json()
        leaf_crt = c.get(f"/api/pki/certs/{cert['id']}/bundle?format=crt")
        leaf_key = c.get(f"/api/pki/certs/{cert['id']}/bundle?format=key")
        assert leaf_crt.status_code == 200 and 'sw-core.crt' in leaf_crt.headers['content-disposition'] and 'BEGIN CERTIFICATE' in leaf_crt.text
        assert leaf_key.status_code == 200 and 'sw-core.key' in leaf_key.headers['content-disposition'] and 'BEGIN' in leaf_key.text and 'PRIVATE KEY' in leaf_key.text
    finally:
        c.delete(f"/api/users/{u['id']}")


def test_vendor_custom_fips_proposals_and_pubkey_san_identity(tmp_path, monkeypatch):
    """Verify non-default FIPS proposals propagate to MikroTik/FortiGate/Cisco and pubkey local_id matches cert SAN."""
    monkeypatch.setenv('VPNAAS_SWANCTL_DIR', str(tmp_path / 'swanctl'))
    monkeypatch.setenv('VPNAAS_CA_KEY', str(tmp_path / 'ca-key.pem'))
    c = client()
    c.post('/api/pki/server/rotate', json={})
    cert = c.post('/api/pki/certs', json={'name': 'dc-core', 'san': 'dc-core@corp.id', 'target_type': 'site'}).json()
    site = c.post('/api/sites', json={
        'name': 'site-core-fips',
        'subnets': '192.168.180.0/24',
        'auth_method': 'pubkey',
        'cert_id': cert['id'],
        'ike_proposals': 'aes256-sha384-modp3072',
        'esp_proposals': 'aes256-sha384',
    }).json()
    try:
        mt = c.get(f"/api/sites/{site['id']}/config?vendor=mikrotik").text
        assert 'hash-algorithm=sha384 enc-algorithm=aes-256 dh-group=modp3072' in mt
        assert 'auth-algorithms=sha384 enc-algorithms=aes-256-cbc' in mt
        # Email SAN must emit user-fqdn (NOT fqdn) and match cert SAN (dc-core@corp.id), not auto ike_id!
        assert 'my-id="user-fqdn:dc-core@corp.id"' in mt

        fg = c.get(f"/api/sites/{site['id']}/config?vendor=fortigate").text
        assert 'set proposal aes256-sha384' in fg and 'set dhgrp 15' in fg
        assert 'set localid "dc-core@corp.id"' in fg

        cs = c.get(f"/api/sites/{site['id']}/config?vendor=cisco").text
        assert 'integrity sha384' in cs and 'group 15' in cs and 'esp-aes 256 esp-sha384-hmac' in cs
        assert 'identity local email dc-core@corp.id' in cs

        gn = c.get(f"/api/sites/{site['id']}/config?vendor=generic").text
        assert 'local_ike_id       = dc-core@corp.id' in gn
        assert 'aes256-sha384-modp3072' in gn

        # Revoking the cert still allows admin to disable the site (enabled=False), but rejects re-enabling!
        assert c.post(f"/api/pki/certs/{cert['id']}/revoke").status_code == 200
        dis = c.put(f"/api/sites/{site['id']}", json={'enabled': False})
        assert dis.status_code == 200 and dis.json()['enabled'] is False
        reen = c.put(f"/api/sites/{site['id']}", json={'enabled': True})
        assert reen.status_code == 422 and 'revoked' in reen.json()['detail']
    finally:
        c.delete(f"/api/sites/{site['id']}")


def test_diagnostics_site_deny_policy_ports_and_vpc():
    """Diagnostics evaluates explicit DENY policies (with port matching) before peer_sites, and checks Site -> VPC."""
    c = client()
    sa = c.post('/api/sites', json={'name': 'diag-a', 'subnets': '192.168.181.0/24', 'allow_vpc': True}).json()
    sb = c.post('/api/sites', json={'name': 'diag-b', 'subnets': '192.168.182.0/24', 'allow_vpc': False, 'peer_sites': [sa['id']]}).json()
    deny_ssh = c.post('/api/policies', json={
        'name': 'deny-b-to-a-ssh',
        'action': 'deny',
        'priority': 10,
        'source_type': 'site',
        'source_ref': sb['id'],
        'destination_type': 'site',
        'destination_ref': sa['id'],
        'protocol': 'tcp',
        'ports': '22',
    }).json()
    try:
        # Site-B -> Site-A TCP 22 must be blocked by deny policy despite peering!
        r_ssh = c.post('/api/diagnostics/check', json={'target': '192.168.181.10', 'source_site_id': sb['id'], 'protocol': 'tcp', 'port': 22}).json()
        assert r_ssh['policy']['allowed'] is False and 'deny-b-to-a-ssh' in r_ssh['policy']['reason']

        # Site-B -> Site-A TCP 443 must still be allowed by bidirectional peering!
        r_https = c.post('/api/diagnostics/check', json={'target': '192.168.181.10', 'source_site_id': sb['id'], 'protocol': 'tcp', 'port': 443}).json()
        assert r_https['policy']['allowed'] is True

        # Site-A (allow_vpc=True) -> VPC allowed; Site-B (allow_vpc=False) -> VPC denied!
        r_a_vpc = c.post('/api/diagnostics/check', json={'target': '10.10.7.50', 'source_site_id': sa['id']}).json()
        assert r_a_vpc['policy']['allowed'] is True and 'allow_vpc' in r_a_vpc['policy']['reason']
        r_b_vpc = c.post('/api/diagnostics/check', json={'target': '10.10.7.50', 'source_site_id': sb['id']}).json()
        assert r_b_vpc['policy']['allowed'] is False
    finally:
        c.delete(f"/api/policies/{deny_ssh['id']}")
        c.delete(f"/api/sites/{sb['id']}")
        c.delete(f"/api/sites/{sa['id']}")
