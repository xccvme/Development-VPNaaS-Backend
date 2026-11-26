"""Tests covering all core bug fixes and security hardening."""
import os
import pytest
from test_api import TestClient
from app import app
import vpn
import network

H = {'X-API-Key': 'test-key'}


def client():
    return TestClient(app, headers=H)


def test_c2s_to_s2s_allowed_via_rt_ipsec_under_route_auto(monkeypatch):
    """When VPNAAS_ROUTE_AUTO=1, C2S user grants targeting enabled S2S subnets must use rt ipsec exists accept, not drop."""
    routes = [
        {'dst': 'default', 'dev': 'ens3', 'metric': 100},
        {'dst': '10.10.7.0/24', 'dev': 'ens8', 'protocol': 'kernel'},
    ]
    monkeypatch.setattr(network, 'snapshot', lambda: routes)
    monkeypatch.setenv('VPNAAS_ROUTE_AUTO', '1')
    user = dict(
        id=50,
        virtual_ip='172.31.201.50',
        username='roamer-s2s',
        password='safe-password',
        enabled=True,
        allowed_cidrs=['10.10.7.0/24', '192.168.10.0/24', '10.99.0.0/24'],
        traffic_mode='split',
    )
    site = dict(id=70, name='site-jkt', subnets='192.168.10.0/24', enabled=True, allow_vpc=True)
    rules = vpn.firewall([], [user], [], sites=[site])
    # Local private NIC subnet -> oifname accept + masquerade
    assert 'ip saddr 172.31.201.50 ip daddr 10.10.7.0/24 oifname "ens8" accept' in rules
    assert 'ip saddr 172.31.201.50 ip daddr 10.10.7.0/24 oifname "ens8" masquerade' in rules
    # S2S site subnet -> rt ipsec exists accept (never leaks plaintext out WAN!)
    assert 'ip saddr 172.31.201.50 ip daddr 192.168.10.0/24 rt ipsec exists accept' in rules
    # Unknown unrouted subnet -> conservatively dropped
    assert 'ip saddr 172.31.201.50 ip daddr 10.99.0.0/24 drop' in rules

    diag = network.diagnostics([user], sites=[site])
    by_cidr = {x['cidr']: x for x in diag['private_routes']}
    assert by_cidr['10.10.7.0/24'] == {'cidr': '10.10.7.0/24', 'interface': 'ens8', 'ready': True, 'via': 'private-nic'}
    assert by_cidr['192.168.10.0/24'] == {'cidr': '192.168.10.0/24', 'interface': 'ipsec', 'ready': True, 'via': 'ipsec-s2s'}
    assert by_cidr['10.99.0.0/24']['ready'] is False


def test_apply_runs_before_revoke_so_failed_apply_does_not_kill_sa(monkeypatch):
    """On PUT/DELETE, apply_configuration runs BEFORE revoke so failed apply preserves active sessions."""
    import app as app_mod
    c = client()
    u = c.post('/api/users', json={'username': 'order-check', 'password': 'safe-password'}).json()
    order = []
    try:
        monkeypatch.setattr(app_mod, 'apply_configuration', lambda: order.append('apply'))
        monkeypatch.setattr(vpn, 'revoke', lambda kind, ident, **kw: order.append(('revoke', kind, ident)))
        r = c.put(f"/api/users/{u['id']}", json={'enabled': False})
        assert r.status_code == 200
        assert order == ['apply', ('revoke', 'users', u['id'])]

        # Simulate apply failure -> revoke must NOT run!
        order.clear()
        def fail_apply():
            order.append('apply_fail')
            raise RuntimeError('nft check failed')
        monkeypatch.setattr(app_mod, 'apply_configuration', fail_apply)
        with pytest.raises(RuntimeError):
            c.put(f"/api/users/{u['id']}", json={'enabled': True})
        assert order == ['apply_fail']
    finally:
        monkeypatch.setattr(app_mod, 'apply_configuration', lambda: None)
        c.delete(f"/api/users/{u['id']}")


def test_direct_s2s_has_runtime_and_resilient_ike_options(monkeypatch):
    c = client()
    row = c.post('/api/connections', json=dict(
        name='direct-rt',
        remote_address='192.0.2.44',
        remote_id='direct-rt.peer',
        local_ts='10.70.0.0/24',
        remote_ts='10.71.0.0/24',
        psk='secure-test-secret',
    )).json()
    i = row['id']
    try:
        # In dry-run direct runtime is unknown
        assert row['runtime_status'] == 'unknown'
        # Rendered config includes unique=replace and dpd_delay=30s
        from store import get
        rendered = vpn.render([get('connections', i)], [])
        block = rendered.split(f'site-{i} {{', 1)[1].split('\n}', 1)[0]
        assert 'unique = replace' in block and 'dpd_delay = 30s' in block

        # Live runtime parsing for direct S2S
        raw = (
            f'list-sa event {{site-{i} {{uniqueid=91 state=ESTABLISHED remote-host=192.0.2.44 remote-port=4500 '
            f'child-sas {{net-{i}-1 {{name=net-{i} state=INSTALLED bytes-in=512 bytes-out=1024}}}}}}}}\n'
            'list-sas reply {}'
        )
        monkeypatch.setattr(vpn, 'run', lambda args, **k: raw)
        monkeypatch.delenv('VPNAAS_DRY_RUN')
        detail = c.get(f'/api/connections/{i}').json()
        assert detail['runtime_status'] == 'active'
        assert detail['remote_host'] == '192.0.2.44:4500'
        assert detail['bytes_in'] == 512 and detail['bytes_out'] == 1024
    finally:
        monkeypatch.setenv('VPNAAS_DRY_RUN', '1')
        c.delete(f'/api/connections/{i}')


def test_custom_larger_pool_scaling_optional(monkeypatch):
    import pool
    monkeypatch.setenv('VPNAAS_POOL_ALLOW_CUSTOM', '1')
    monkeypatch.setenv('VPNAAS_POOL_CIDR', '10.250.0.0/22')
    net = pool.network()
    assert str(net) == '10.250.0.0/22' and net.num_addresses == 1024
    # Reject public CIDR or oversized /16 even with custom enabled
    monkeypatch.setenv('VPNAAS_POOL_CIDR', '10.0.0.0/16')
    with pytest.raises(ValueError):
        pool.network()
    monkeypatch.setenv('VPNAAS_POOL_CIDR', '8.8.8.0/24')
    with pytest.raises(ValueError):
        pool.network()


def test_cert_expiry_recomputed_and_revoke_rolls_back_on_error(tmp_path, monkeypatch):
    """GET /api/pki/certs recomputes expired/days_remaining dynamically, and revoke rolls back DB on CRL failure."""
    import json
    import pki
    from store import db, get, lock

    monkeypatch.setenv('VPNAAS_SWANCTL_DIR', str(tmp_path / 'swanctl'))
    monkeypatch.setenv('VPNAAS_CA_KEY', str(tmp_path / 'ca-key.pem'))
    c = client()
    cert = c.post('/api/pki/certs', json={'name': 'exp-check', 'target_type': 'user', 'validity_days': 10}).json()
    cid = cert['id']
    # Simulate an old stored row whose not_after is already in the past while persisted expired=False
    with lock:
        raw = get('certs', cid)
        raw['not_after'] = '2020-01-01T00:00:00Z'
        raw['days_remaining'] = 10
        raw['expired'] = False
        body = {k: v for k, v in raw.items() if k != 'id'}
        db.execute('UPDATE objects SET body=? WHERE id=?', (json.dumps(body), cid))
        db.commit()

    detail = c.get(f'/api/pki/certs/{cid}').json()
    assert detail['expired'] is True and detail['days_remaining'] < 0
    listed = [x for x in c.get('/api/pki/certs').json() if x['id'] == cid][0]
    assert listed['expired'] is True and listed['days_remaining'] < 0

    # If rebuild_crl raises, DB must rollback so cert stays revoked=False
    def boom(_rows):
        raise RuntimeError('crl write failed')

    monkeypatch.setattr(pki, 'rebuild_crl', boom)
    with pytest.raises(RuntimeError):
        c.post(f'/api/pki/certs/{cid}/revoke')
    assert c.get(f'/api/pki/certs/{cid}').json()['revoked'] is False


def test_diagnostics_directional_intersite_allow_and_route_site_overlap():
    """Directional inter-site ALLOW policy only permits src->dst in diagnostics; site routes cannot overlap other sites."""
    c = client()
    sa = c.post('/api/sites', json={'name': 'dir-site-a', 'subnets': '192.168.140.0/24', 'allow_vpc': False}).json()
    sb = c.post('/api/sites', json={'name': 'dir-site-b', 'subnets': '192.168.141.0/24', 'allow_vpc': False}).json()
    pol = None
    rt = None
    try:
        # Directional ALLOW: Site-A -> Site-B only (not peered)
        pol = c.post('/api/policies', json={
            'name': 'allow-a-to-b-443',
            'action': 'allow',
            'source_type': 'site', 'source_ref': sa['id'],
            'destination_type': 'site', 'destination_ref': sb['id'],
            'protocol': 'tcp', 'ports': '443',
        }).json()
        fwd = c.post('/api/diagnostics/check', json={
            'source_site_id': sa['id'], 'target': '192.168.141.10', 'protocol': 'tcp', 'port': 443,
        }).json()
        rev = c.post('/api/diagnostics/check', json={
            'source_site_id': sb['id'], 'target': '192.168.140.10', 'protocol': 'tcp', 'port': 443,
        }).json()
        assert fwd['policy']['allowed'] is True
        assert rev['policy']['allowed'] is False

        # Route attached to Site-A overlapping Site-B's subnet must be rejected (422)
        bad_rt = c.post('/api/routes', json={
            'name': 'overlap-site-b', 'destination_cidr': '192.168.141.0/25', 'site_id': sa['id'],
        })
        assert bad_rt.status_code == 422

        # Valid non-overlapping route attached to Site-A blocks new Site-C overlapping that route
        rt = c.post('/api/routes', json={
            'name': 'extra-site-a', 'destination_cidr': '192.168.142.0/24', 'site_id': sa['id'],
        }).json()
        bad_site = c.post('/api/sites', json={'name': 'overlap-route-a', 'subnets': '192.168.142.0/24'})
        assert bad_site.status_code == 422
    finally:
        if pol:
            c.delete(f"/api/policies/{pol['id']}")
        if rt:
            c.delete(f"/api/routes/{rt['id']}")
        c.delete(f"/api/sites/{sb['id']}")
        c.delete(f"/api/sites/{sa['id']}")
