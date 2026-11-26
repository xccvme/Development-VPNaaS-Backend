"""Static routes, Token-based RBAC auth (Bearer & X-API-Key), readiness, gateway metadata, monitoring, logs, diagnostics, and audit filtering."""
from test_api import TestClient
from app import app
import vpn

H = {'X-API-Key': 'test-key'}


def client(headers=None):
    return TestClient(app, headers=headers or H)


def test_token_based_auth_bearer_and_rbac():
    admin = client()
    # Public /docs and /openapi.json disabled by default; authenticated /api/openapi.json works
    assert TestClient(app).get('/openapi.json').status_code == 404
    assert TestClient(app).get('/api/openapi.json').status_code == 401
    assert admin.get('/api/openapi.json').status_code == 200

    # Create operator & readonly tokens
    op = admin.post('/api/tokens', json={'name': 'cp-operator', 'role': 'operator', 'expires_days': 30})
    ro = admin.post('/api/tokens', json={'name': 'cp-readonly', 'role': 'readonly'})
    assert op.status_code == 200 and ro.status_code == 200
    assert 'no-store' in op.headers['cache-control']
    op_tok = op.json()['token']
    ro_tok = ro.json()['token']

    # Plaintext token never appears on GET /api/tokens
    listed = admin.get('/api/tokens').json()
    assert op_tok not in str(listed) and ro_tok not in str(listed)

    # Bearer authentication works!
    ro_client = TestClient(app, headers={'Authorization': f'Bearer {ro_tok}'})
    op_client = TestClient(app, headers={'Authorization': f'Bearer {op_tok}'})

    assert ro_client.get('/api/health').status_code == 200
    assert ro_client.get('/api/gateway').status_code == 200
    # Readonly cannot mutate or manage tokens
    assert ro_client.post('/api/groups', json={'name': 'forbidden-grp'}).status_code == 403
    assert ro_client.get('/api/tokens').status_code == 403

    # Operator can CRUD VPN resources & download profiles, but cannot manage /api/tokens
    u = op_client.post('/api/users', json={'username': 'op-created', 'password': 'safe-password-1'}).json()
    assert ro_client.get(f"/api/users/{u['id']}/profile").status_code == 403
    assert op_client.get(f"/api/users/{u['id']}/profile").status_code == 200
    assert op_client.get('/api/tokens').status_code == 403
    assert op_client.delete(f"/api/users/{u['id']}").status_code == 200

    # Revoke token -> immediate 401
    assert admin.delete(f"/api/tokens/{ro.json()['id']}").status_code == 200
    assert ro_client.get('/api/health').status_code == 401
    admin.delete(f"/api/tokens/{op.json()['id']}")


def test_static_routes_crud_and_live():
    c = client()
    r = c.post('/api/routes', json={
        'name': 'to-dnet-db',
        'destination_cidr': '10.120.0.5/24',
        'gateway': '10.10.7.1',
        'interface': 'ens8',
        'metric': 50,
    })
    assert r.status_code == 200, r.text
    row = r.json()
    try:
        assert row['destination_cidr'] == '10.120.0.0/24' and row['metric'] == 50
        # Duplicate destination CIDR -> 409
        assert c.post('/api/routes', json={'name': 'dup-dst', 'destination_cidr': '10.120.0.0/24', 'gateway': '10.10.7.2'}).status_code == 409
        # /0 rejected
        assert c.post('/api/routes', json={'name': 'bad-default', 'destination_cidr': '0.0.0.0/0', 'gateway': '10.10.7.1'}).status_code == 422
        # Missing gateway/interface/site_id rejected
        assert c.post('/api/routes', json={'name': 'no-nexthop', 'destination_cidr': '10.121.0.0/24'}).status_code == 422

        live = c.get('/api/routes/live').json()
        assert any(x['id'] == row['id'] and x['sync_status'] == 'unknown' for x in live['static_routes'])

        # Edit route: change gateway, metric, description, and verify kernel proto-188 metric replacement deletes stale metric
        upd = c.put(f"/api/routes/{row['id']}", json={
            'gateway': '10.10.7.254',
            'metric': 25,
            'description': 'updated db route',
        })
        assert upd.status_code == 200 and upd.json()['gateway'] == '10.10.7.254' and upd.json()['metric'] == 25

        # Verify local static route gets firewall forward + SNAT rules for S2S allow_vpc & C2S
        from store import rows as db_rows
        sa = c.post('/api/sites', json={'name': 'rt-site-a', 'subnets': '192.168.180.0/24', 'allow_vpc': True}).json()
        sr = None
        try:
            fw = vpn.firewall([], [], [], sites=db_rows('sites'), routes=db_rows('routes'))
            assert 'ip saddr 192.168.180.0/24 ip daddr 10.120.0.0/24 meta ipsec exists accept' in fw
            assert 'ip saddr 10.120.0.0/24 ip daddr 192.168.180.0/24 rt ipsec exists accept' in fw
            assert 'ip daddr 10.120.0.0/24 oifname "ens8" snat to' in fw

            # Site-backed static route (site_id) wires into site remote_ts, vendor config, C2S effective_cidrs, and firewall!
            sr = c.post('/api/routes', json={
                'name': 'extra-behind-site-a',
                'destination_cidr': '10.130.0.0/24',
                'site_id': sa['id'],
            }).json()
            rendered = vpn.render([], [], sites=db_rows('sites'), routes=db_rows('routes'))
            assert 'remote_ts = 192.168.180.0/24,10.130.0.0/24' in rendered
            cfg = c.get(f"/api/sites/{sa['id']}/config?vendor=swanctl").text
            assert 'local_ts = 192.168.180.0/24,10.130.0.0/24' in cfg

            # Switching route from gateway to site_id clears gateway cleanly
            sw = c.put(f"/api/routes/{row['id']}", json={'gateway': None, 'interface': None, 'site_id': sa['id']})
            assert sw.status_code == 200 and sw.json()['gateway'] is None and sw.json()['site_id'] == sa['id']
        finally:
            if sr:
                c.delete(f"/api/routes/{sr['id']}")
            c.delete(f"/api/routes/{row['id']}")
            c.delete(f"/api/sites/{sa['id']}")
    finally:
        c.delete(f"/api/routes/{row['id']}")


def test_apply_routes_replaces_changed_metric_and_deletes_old(monkeypatch):
    import routing, subprocess
    monkeypatch.delenv('VPNAAS_DRY_RUN', raising=False)
    monkeypatch.setattr(routing, '_kernel_owned_routes', lambda: [
        {'dst': '10.120.0.0/24', 'gateway': '10.10.7.1', 'metric': 100, 'protocol': '188'},
        {'dst': '10.121.0.0/24', 'gateway': '10.10.7.1', 'metric': 100, 'protocol': '188'},
    ])
    calls = []
    monkeypatch.setattr(subprocess, 'run', lambda args, **kw: calls.append(args))
    res = routing.apply_routes([
        {'destination_cidr': '10.120.0.0/24', 'gateway': '10.10.7.254', 'metric': 50, 'enabled': True},
    ])
    assert res == {'applied': 1, 'deleted': 2, 'dry_run': False}
    assert ['ip', '-4', 'route', 'replace', '10.120.0.0/24', 'via', '10.10.7.254', 'metric', '50', 'proto', '188'] in calls
    assert ['ip', '-4', 'route', 'del', '10.120.0.0/24', 'metric', '100', 'proto', '188'] in calls
    assert ['ip', '-4', 'route', 'del', '10.121.0.0/24', 'metric', '100', 'proto', '188'] in calls
    monkeypatch.setenv('VPNAAS_DRY_RUN', '1')


def test_readiness_gateway_monitoring_logs_diagnostics_and_disconnect(monkeypatch):
    monkeypatch.setenv('VPNAAS_REGION', 'jakarta')
    monkeypatch.setenv('VPNAAS_TENANT_ID', 'tenant-dcloud-01')
    c = client()

    # Readiness & Gateway metadata
    rdy = c.get('/api/ready')
    assert rdy.status_code == 200 and rdy.json()['ready'] is True
    gw = c.get('/api/gateway').json()
    assert gw['region'] == 'jakarta' and gw['tenant_id'] == 'tenant-dcloud-01'
    assert gw['capabilities']['ikev2_s2s_multisite'] is True and gw['capabilities']['pki_crl'] is True

    # Logs redaction & dry-run
    from app import _redact_log
    assert 'secret-pass' not in _redact_log('password=secret-pass psk=my-secret-psk vpnaas_ABCDEF123456')
    logs = c.get('/api/logs?source=strongswan&lines=50')
    assert logs.status_code == 200 and logs.json()['unit'] == 'strongswan.service'

    # Diagnostics check + Monitoring tunnels + User disconnect + Audit filtering
    site = c.post('/api/sites', json={'name': 'diag-site', 'subnets': '10.200.0.0/24'}).json()
    u = c.post('/api/users', json={'username': 'diag-user', 'password': 'safe-password-9', 'allowed_sites': [site['id']]}).json()
    try:
        diag_ok = c.post('/api/diagnostics/check', json={'target': '10.200.0.50', 'source_user_id': u['id'], 'ping': True}).json()
        assert diag_ok['policy']['allowed'] is True
        assert diag_ok['tunnel']['type'] == 'site' and diag_ok['ping']['skipped'] is True

        diag_deny = c.post('/api/diagnostics/check', json={'target': '10.201.0.50', 'source_user_id': u['id']}).json()
        assert diag_deny['policy']['allowed'] is False

        mon = c.get('/api/monitoring/tunnels').json()
        assert mon['totals']['sites_total'] >= 1 and any(x['id'] == u['id'] for x in mon['c2s'])

        # Explicit user disconnect (dry-run)
        disc = c.post(f"/api/users/{u['id']}/disconnect")
        assert disc.status_code == 200 and disc.json()['ok'] is True

        # Single-session disconnect with mocked live SA
        raw = (
            f"list-sa event {{user-{u['id']} {{uniqueid=303 state=ESTABLISHED remote-eap-id=diag-user "
            f"remote-host=192.0.2.5 remote-vips=[{u['virtual_ip']}] "
            f"child-sas {{c2s-{u['id']} {{uniqueid=304 state=INSTALLED bytes-in=10 bytes-out=20}}}}}}}}\n"
            'list-sas reply {}'
        )
        calls = []
        monkeypatch.setattr(vpn, 'run', lambda args, **k: calls.append(args) or (raw if '--list-sas' in args else 'terminated'))
        monkeypatch.delenv('VPNAAS_DRY_RUN')
        assert c.post(f"/api/users/{u['id']}/sessions/999/disconnect").status_code == 404
        d1 = c.post(f"/api/users/{u['id']}/sessions/303/disconnect")
        assert d1.status_code == 200 and d1.json()['disconnected'] == '303'
        assert any('--ike-id' in a and '303' in a for a in calls)
        monkeypatch.setenv('VPNAAS_DRY_RUN', '1')

        # Audit filter & pagination
        aud = c.get('/api/audit?resource=sites&limit=5&offset=0').json()
        assert len(aud) >= 1 and all(x['resource'] == 'sites' for x in aud)
    finally:
        monkeypatch.setenv('VPNAAS_DRY_RUN', '1')
        c.delete(f"/api/users/{u['id']}")
        c.delete(f"/api/sites/{site['id']}")
