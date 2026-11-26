"""PKI CA, Server Cert Rotation, Client/Site X.509 Certs, PKCS#12, CRL & Cert-based Auth."""
from cryptography import x509
from cryptography.hazmat.primitives.serialization import pkcs12
from test_api import TestClient
from app import app
import vpn

H = {'X-API-Key': 'test-key'}


def client():
    return TestClient(app, headers=H)


def test_pki_lifecycle_certs_pkcs12_crl_and_pubkey_render(tmp_path, monkeypatch):
    monkeypatch.setenv('VPNAAS_SWANCTL_DIR', str(tmp_path / 'swanctl'))
    monkeypatch.setenv('VPNAAS_CA_KEY', str(tmp_path / 'ca-key.pem'))
    c = client()

    # Rotate/initialize CA + server cert
    rot = c.post('/api/pki/server/rotate', json={'extra_sans': ['vpn.tenant.dcloud.id'], 'validity_days': 365})
    assert rot.status_code == 200, rot.text
    rot_data = rot.json()
    assert rot_data['rotated'] is True and '203.0.113.10' in rot_data['san_ips']
    assert 'vpn.tenant.dcloud.id' in rot_data['san_dns']

    # CA status & download
    ca = c.get('/api/pki/ca').json()
    assert ca['present'] is True and ca['has_private_key'] is True
    ca_pem = c.get('/api/pki/ca/cert').text
    assert 'BEGIN CERTIFICATE' in ca_pem

    # Issue user cert and site cert
    ucert = c.post('/api/pki/certs', json={'name': 'alice-cert', 'san': 'alice@dcloud.id', 'target_type': 'user', 'validity_days': 180}).json()
    scert = c.post('/api/pki/certs', json={'name': 'hq-cert', 'san': 'hq@dcloud.id', 'target_type': 'site', 'validity_days': 365}).json()
    assert 'private_key_pem' not in ucert and ucert['revoked'] is False

    # Download PEM bundle & PKCS#12 bundle
    pem_bundle = c.get(f"/api/pki/certs/{ucert['id']}/bundle?format=pem")
    assert pem_bundle.status_code == 200 and 'no-store' in pem_bundle.headers['cache-control']
    assert 'BEGIN RSA PRIVATE KEY' in pem_bundle.json()['private_key_pem']

    p12_resp = c.get(f"/api/pki/certs/{ucert['id']}/bundle?format=p12&passphrase=test-pass")
    assert p12_resp.status_code == 200 and p12_resp.headers['content-type'] == 'application/x-pkcs12'
    key, cert, cas = pkcs12.load_key_and_certificates(p12_resp.content, b'test-pass')
    assert key is not None and cert is not None and len(cas) == 1

    # Bind certs to pubkey user, eap-tls user, and pubkey site
    u_pub = c.post('/api/users', json={
        'username': 'alice-pubkey', 'auth_method': 'pubkey', 'cert_id': ucert['id'],
        'allowed_cidrs': ['10.10.7.0/24'],
    }).json()
    u_tls = c.post('/api/users', json={
        'username': 'alice-eaptls', 'auth_method': 'eap-tls', 'cert_id': ucert['id'],
        'allowed_cidrs': ['10.10.7.0/24'],
    }).json()
    s_pub = c.post('/api/sites', json={
        'name': 'hq-cert-site', 'auth_method': 'pubkey', 'cert_id': scert['id'],
        'subnets': '10.66.0.0/24',
    }).json()
    try:
        from store import rows
        rendered = vpn.render([], rows('users'), sites=rows('sites'), certs=rows('certs'))
        pub_block = rendered.split(f"user-{u_pub['id']} {{", 1)[1].split('\n}', 1)[0]
        assert 'auth = pubkey' in pub_block and 'id = alice@dcloud.id' in pub_block and 'revocation = relaxed' in pub_block
        tls_block = rendered.split(f"user-{u_tls['id']} {{", 1)[1].split('\n}', 1)[0]
        assert 'auth = eap-tls' in tls_block and 'eap_id = alice-eaptls' in tls_block
        site_block = rendered.split(f"site-n-{s_pub['id']} {{", 1)[1].split('\n}', 1)[0]
        assert 'auth = pubkey' in site_block and 'id = hq@dcloud.id' in site_block

        # Revoke cert -> generates valid X.509 CRL containing the revoked serial!
        rev = c.post(f"/api/pki/certs/{ucert['id']}/revoke")
        assert rev.status_code == 200 and rev.json()['revoked'] is True and rev.json()['crl_entries'] >= 1
        crl_pem = c.get('/api/pki/crl').text
        crl_obj = x509.load_pem_x509_crl(crl_pem.encode('utf-8'))
        assert crl_obj.get_revoked_certificate_by_serial_number(int(ucert['serial'], 16)) is not None

        # Binding a revoked cert to a new user must be rejected with 422
        assert c.post('/api/users', json={
            'username': 'revoked-attempt', 'auth_method': 'pubkey', 'cert_id': ucert['id'],
            'allowed_cidrs': ['10.10.7.0/24'],
        }).status_code == 422
    finally:
        c.delete(f"/api/users/{u_pub['id']}")
        c.delete(f"/api/users/{u_tls['id']}")
        c.delete(f"/api/sites/{s_pub['id']}")
