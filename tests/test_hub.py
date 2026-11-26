"""VPN Hub (hub-and-spoke S2S): /api/connections with topology=hub."""
import pytest
from fastapi import HTTPException
from test_api import TestClient
from app import app
import vpn

H = {'X-API-Key': 'test-key'}
SITE_A = dict(name='Kantor A', address='198.51.100.20', subnets='10.10.7.0/24', psk='hub-site-a-secret-123')
SITE_B = dict(name='Kantor B', subnets='172.16.1.0/24, 10.221.61.0/24,10.221.61.0/24')


def client():
    return TestClient(app, headers=H)


def body(**kw):
    data = dict(name='hub-test', site_a=dict(SITE_A), site_b=dict(SITE_B))
    data.update(kw)
    return data


def make(c, **kw):
    r = c.post('/api/connections', json=body(**kw))
    assert r.status_code == 200, r.text
    return r.json()


def validate(data, old=None):
    from store import validate as v
    return v('connections', data, old)


# ---------- validation ----------

def test_create_defaults_and_redaction():
    c = client()
    row = make(c)
    try:
        assert row['topology'] == 'hub' and row['enabled'] is True
        a, b = row['site_a'], row['site_b']
        assert a['address'] == '198.51.100.20' and b['address'] == '%any'
        assert a['id'] == 'hub-test-a@vpnaas' and b['id'] == 'hub-test-b@vpnaas'
        assert b['subnets'] == '172.16.1.0/24,10.221.61.0/24'
        assert a['nat'] is True and b['nat'] is True
        assert a['psk_set'] is True and b['psk_set'] is True
        assert 'psk' not in a and 'psk' not in b and 'hub-site-a-secret-123' not in str(row)
        for s in (a, b):
            assert s['status'] == 'unknown' and s['remote_host'] is None
            assert s['bytes_in'] == 0 and s['bytes_out'] == 0
        from store import get
        stored = get('connections', row['id'])
        assert stored['site_a']['psk'] == 'hub-site-a-secret-123'
        assert len(stored['site_b']['psk']) == 32  # generated
        got = c.get(f"/api/connections/{row['id']}").json()
        assert got['site_b']['subnets'] == '172.16.1.0/24,10.221.61.0/24' and 'psk' not in got['site_b']
        assert any(x['id'] == row['id'] for x in c.get('/api/connections').json())
    finally:
        assert c.delete(f"/api/connections/{row['id']}").status_code == 200


def test_put_merges_nested_and_keeps_psk():
    c = client()
    row = make(c)
    try:
        r = c.put(f"/api/connections/{row['id']}", json={'site_a': {'subnets': '10.10.8.0/24', 'psk': ''}, 'site_b': {'nat': False}})
        assert r.status_code == 200, r.text
        from store import get
        stored = get('connections', row['id'])
        assert stored['site_a']['psk'] == 'hub-site-a-secret-123'
        assert stored['site_a']['subnets'] == '10.10.8.0/24' and stored['site_a']['address'] == '198.51.100.20'
        assert stored['site_b']['nat'] is False and stored['site_b']['subnets'] == '172.16.1.0/24,10.221.61.0/24'
        r = c.put(f"/api/connections/{row['id']}", json={'site_b': {'psk': 'new-site-b-secret-456'}})
        assert get('connections', row['id'])['site_b']['psk'] == 'new-site-b-secret-456'
        assert c.put(f"/api/connections/{row['id']}", json={'topology': 'direct'}).status_code == 422
    finally:
        c.delete(f"/api/connections/{row['id']}")


@pytest.mark.parametrize('patch', [
    {'site_a': dict(SITE_A, bogus=1)},
    {'site_c': {}},
    {'remote_address': '198.51.100.1'},
    {'topology': 'mesh'},
    {'site_a': dict(SITE_A, psk='short')},
    {'site_a': dict(SITE_A, subnets='0.0.0.0/0')},
    {'site_a': dict(SITE_A, subnets='')},
    {'site_a': dict(SITE_A, subnets=','.join(f'10.9.{n}.0/24' for n in range(9)))},
    {'site_a': dict(SITE_A, subnets='172.16.1.128/25')},          # overlaps B
    {'site_a': dict(SITE_A, subnets='172.31.201.0/25')},          # overlaps C2S pool
    {'site_a': dict(SITE_A, subnets='fd00::/64')},
    {'site_a': dict(SITE_A, address='bad address!')},
    {'site_a': dict(SITE_A, id='has space')},
    {'site_a': dict(SITE_A, nat='yes')},
    {'site_a': 'x'},
    {'site_b': dict(SITE_B, id='hub-test-a@vpnaas')},            # A == B id
    {'site_b': {k: v for k, v in SITE_B.items() if k != 'subnets'}},
    {'enabled': 'true'},
])
def test_rejected(patch):
    with pytest.raises(HTTPException) as e:
        validate(body(**patch))
    assert e.value.status_code == 422


def test_hostname_and_any_address():
    d = validate(body(site_a=dict(SITE_A, address='spoke.example.net'), site_b=dict(SITE_B, address='')))
    assert d['site_a']['address'] == 'spoke.example.net' and d['site_b']['address'] == '%any'


def test_site_id_unique_across_connections():
    c = client()
    row = make(c)
    legacy = c.post('/api/connections', json=dict(name='legacy-x', remote_address='192.0.2.30', remote_id='legacy.peer',
                                                 local_ts='10.50.0.0/24', remote_ts='10.51.0.0/24', psk='secure-test-secret'))
    assert legacy.status_code == 200 and legacy.json()['topology'] == 'direct'
    try:
        r = c.post('/api/connections', json=body(name='hub-other', site_a=dict(SITE_A, id='hub-test-b@vpnaas')))
        assert r.status_code == 422 and 'unik' in r.json()['detail']
        r = c.post('/api/connections', json=body(name='hub-other2', site_a=dict(SITE_A, id='legacy.peer')))
        assert r.status_code == 422
        r = c.post('/api/connections', json=body(name='hub-test'))
        assert r.status_code == 409
    finally:
        c.delete(f"/api/connections/{row['id']}")
        c.delete(f"/api/connections/{legacy.json()['id']}")


def test_legacy_direct_unchanged():
    c = client()
    r = c.post('/api/connections', json=dict(name='legacy-d', remote_address='192.0.2.31', local_ts='10.60.0.0/24',
                                            remote_ts='10.61.0.0/24', psk='secure-test-secret', topology='direct'))
    assert r.status_code == 200, r.text
    row = r.json()
    try:
        assert row['topology'] == 'direct' and row['remote_id'] == '192.0.2.31' and 'psk' not in row
        assert c.post(f"/api/connections/{row['id']}/sites/a/connect").status_code == 409
        assert c.get(f"/api/connections/{row['id']}/sites/a/config").status_code == 409
    finally:
        c.delete(f"/api/connections/{row['id']}")


def test_legacy_row_without_topology_reported_direct():
    from store import public
    assert public(dict(id=30, name='x', remote_address='192.0.2.5', psk='s'))['topology'] == 'direct'


# ---------- hub rendering ----------

HUB = dict(id=40, name='example', enabled=True, topology='hub',
           site_a=dict(name='A', address='198.51.100.20', id='example-a@vpnaas', psk='psk-a-0123456789abc', subnets='10.10.7.0/24', nat=True),
           site_b=dict(name='B', address='%any', id='example-b@vpnaas', psk='psk-b-0123456789abc', subnets='172.16.1.0/24,10.221.61.0/24', nat=True))
LEGACY = dict(id=30, enabled=True, remote_address='192.0.2.20', remote_id='192.0.2.20', psk='secure-test-secret',
              local_ts='172.16.50.0/24', remote_ts='172.16.1.0/24')


def conn_block(text, name):
    start = text.index(name + ' {')
    return text[start:text.index('\n}', start)]


def test_render_hub_conns():
    text = vpn.render([LEGACY, HUB], [])
    a, b = conn_block(text, 'hub-40-a'), conn_block(text, 'hub-40-b')
    assert 'remote_addrs = 198.51.100.20' in a and 'remote_addrs = %any' in b
    assert 'id = example-a@vpnaas' in a and 'id = example-b@vpnaas' in b
    assert 'hub-40-a-net {' in a and ' local_ts = 172.16.1.0/24,10.221.61.0/24\n remote_ts = 10.10.7.0/24\n' in a
    assert 'hub-40-b-net {' in b and ' local_ts = 10.10.7.0/24\n remote_ts = 172.16.1.0/24,10.221.61.0/24\n' in b
    for blk in (a, b):
        assert 'proposals = aes256-sha256-modp2048' in blk and 'esp_proposals = aes256-sha256' in blk
        assert 'dpd_delay' in blk and 'start_action = none' in blk
        assert ' encap = yes\n' in blk
        assert 'modp1024' not in blk
    assert 'ike-hub-40-a { id-1 = 203.0.113.10\n id-2 = example-a@vpnaas\n secret = "psk-a-0123456789abc"' in text
    assert 'id-2 = example-b@vpnaas\n secret = "psk-b-0123456789abc"' in text
    # legacy block untouched
    assert 'site-30 {' in text and 'net-30 {' in text


def test_render_disabled_hub_absent():
    text = vpn.render([dict(HUB, enabled=False)], [])
    assert 'hub-40' not in text


def test_firewall_hub_pairs():
    rules = vpn.firewall([HUB], [], [])
    fwd = rules.split('chain forward')[1].split('chain nat')[0]
    mss = rules.split('chain mss')[1].split('chain forward')[0]
    for b in ('172.16.1.0/24', '10.221.61.0/24'):
        assert f'ip saddr 10.10.7.0/24 ip daddr {b} meta ipsec exists rt ipsec exists accept' in fwd
        assert f'ip saddr {b} ip daddr 10.10.7.0/24 meta ipsec exists rt ipsec exists accept' in fwd
        assert f'ip saddr 10.10.7.0/24 ip daddr {b} meta ipsec exists tcp flags & (syn|rst) == syn tcp option maxseg size > 1300 tcp option maxseg size set 1300' in mss
        assert f'ip saddr {b} ip daddr 10.10.7.0/24 meta ipsec exists tcp flags' in mss
    assert '10.221.61.0/24,' not in rules


def test_reload_unloads_hub_conns_only(monkeypatch):
    events = []

    class Session:
        def get_conns(self):
            return {'conns': [b'user-3', b'hub-40-a', b'hub-40-b', b'hub-40-c', b'vpnaas-hub-1-a', b'site-30', b'foreign']}

        def unload_conn(self, message):
            events.append(message['name'])
    monkeypatch.setattr(vpn, 'vici_session', lambda: Session(), raising=False)
    monkeypatch.setattr(vpn, 'run', lambda args: None)
    vpn.reload_config()
    assert events == [b'user-3', b'hub-40-a', b'hub-40-b', b'site-30']


# ---------- spoke config / script ----------

def test_spoke_swanctl_config():
    c = client()
    row = make(c)
    try:
        r = c.get(f"/api/connections/{row['id']}/sites/a/config?format=swanctl")
        assert r.status_code == 200
        assert r.headers['content-type'].startswith('text/plain')
        assert 'attachment' in r.headers['content-disposition'] and 'Hub-hub-test-Site-A.conf' in r.headers['content-disposition']
        assert 'no-store' in r.headers['cache-control']
        t = r.text
        i = row['id']
        assert f'vpnaas-hub-{i}-a {{' in t and f'vpnaas-hub-{i}-a-net {{' in t
        assert 'remote_addrs = 203.0.113.10' in t
        assert 'local {\n      auth = psk\n      id = hub-test-a@vpnaas' in t
        assert 'remote {\n      auth = psk\n      id = 203.0.113.10' in t
        assert 'local_ts = 10.10.7.0/24\n' in t and 'remote_ts = 172.16.1.0/24,10.221.61.0/24\n' in t
        assert 'start_action = start' in t and 'dpd_action = restart' in t and 'close_action = start' in t
        assert '    encap = yes\n' in t  # ESP in UDP 4500: raw ESP (proto 50) is often filtered by cloud SGs
        assert 'secret = "hub-site-a-secret-123"' in t
        b = c.get(f"/api/connections/{row['id']}/sites/b/config").text  # default swanctl
        assert 'local_ts = 172.16.1.0/24,10.221.61.0/24\n' in b and 'remote_ts = 10.10.7.0/24\n' in b
        assert c.get(f"/api/connections/{row['id']}/sites/c/config").status_code in (404, 422)
        assert c.get(f"/api/connections/{row['id']}/sites/a/config?format=xml").status_code == 422
        assert c.get('/api/connections/999999/sites/a/config').status_code == 404
    finally:
        c.delete(f"/api/connections/{row['id']}")


def test_spoke_script(tmp_path):
    import subprocess
    c = client()
    row = make(c)
    try:
        r = c.get(f"/api/connections/{row['id']}/sites/b/config?format=script")
        assert r.status_code == 200 and 'Setup-Hub-hub-test-Site-B.sh' in r.headers['content-disposition']
        s = r.text
        i = row['id']
        assert s.startswith('#!/usr/bin/env bash\n') and 'set -euo pipefail' in s
        assert f'/etc/swanctl/conf.d/vpnaas-hub-{i}-b.conf' in s and 'chmod 600' in s or 'install -m 600' in s
        assert f'vpnaas_spoke_{i}' in s and '--uninstall' in s
        assert 'flush ruleset' not in s and '--clear' not in s
        assert 'strongswan-swanctl' in s and 'charon-systemd' in s
        assert 'net.ipv4.ip_forward' in s and 'masquerade' in s and 'maxseg' in s
        assert 'swanctl --load-all' in s and '--initiate' in s
        assert 'NAT=1' in s
        p = tmp_path / 's.sh'
        p.write_text(s, encoding='utf-8', newline='\n')
        import os, shutil
        bash = shutil.which('bash') if os.name == 'posix' else next(
            (b for b in (r'C:\Program Files\Git\bin\bash.exe', r'C:\Program Files\Git\usr\bin\bash.exe') if os.path.exists(b)),
            None,
        )
        if bash:
            assert subprocess.run([bash, '-n', str(p)]).returncode == 0
        c.put(f"/api/connections/{row['id']}", json={'site_b': {'nat': False}})
        s2 = c.get(f"/api/connections/{row['id']}/sites/b/config?format=script").text
        assert 'NAT=0' in s2
    finally:
        c.delete(f"/api/connections/{row['id']}")


# ---------- connect / disconnect ----------

def test_connect_any_409_and_actions(monkeypatch):
    c = client()
    row = make(c)
    calls = []
    monkeypatch.setattr(vpn, 'run', lambda args, **k: calls.append(args) or 'completed successfully')
    monkeypatch.delenv('VPNAAS_DRY_RUN')
    try:
        i = row['id']
        r = c.post(f'/api/connections/{i}/sites/b/connect')
        assert r.status_code == 409
        assert r.json()['detail'] == 'Site di belakang NAT/IP dinamis: connect dari sisi site (jalankan script Configure)'
        calls.clear()
        r = c.post(f'/api/connections/{i}/sites/a/connect')
        assert r.status_code == 200, r.text
        assert ['swanctl', '--initiate', '--child', f'hub-{i}-a-net', '--timeout', '12'] in calls
        calls.clear()
        r = c.post(f'/api/connections/{i}/sites/b/disconnect')
        assert r.status_code == 200
        assert calls == [['swanctl', '--terminate', '--ike', f'hub-{i}-b', '--timeout', '12']]
        assert c.post(f'/api/connections/{i}/initiate').status_code == 409
    finally:
        monkeypatch.setenv('VPNAAS_DRY_RUN', '1')
        c.delete(f"/api/connections/{row['id']}")


def test_connect_disabled_409():
    c = client()
    row = make(c, enabled=False)
    try:
        assert c.post(f"/api/connections/{row['id']}/sites/a/connect").status_code == 409
    finally:
        c.delete(f"/api/connections/{row['id']}")


# ---------- runtime ----------

def test_runtime_status(monkeypatch):
    c = client()
    row = make(c)
    i = row['id']
    raw = (f'list-sa event {{hub-{i}-a {{uniqueid=50 state=ESTABLISHED remote-host=198.51.100.20 remote-port=4500 '
           f'child-sas {{hub-{i}-a-net-7 {{name=hub-{i}-a-net state=INSTALLED bytes-in=100 bytes-out=200}}}}}}}}\n'
           f'list-sa event {{hub-{i}-b {{uniqueid=51 state=ESTABLISHED remote-host=192.0.2.9 remote-port=61000 child-sas {{}}}}}}\n'
           'list-sa event {site-30 {uniqueid=45 state=ESTABLISHED child-sas {net-30-1 {name=net-30 state=INSTALLED}}}}\n'
           'list-sas reply {}')
    monkeypatch.setattr(vpn, 'run', lambda args, **k: raw)
    monkeypatch.delenv('VPNAAS_DRY_RUN')
    try:
        got = c.get(f'/api/connections/{i}').json()
        assert got['site_a']['status'] == 'active' and got['site_a']['remote_host'] == '198.51.100.20:4500'
        assert got['site_a']['bytes_in'] == 100 and got['site_a']['bytes_out'] == 200
        assert got['site_b']['status'] == 'down' and got['site_b']['remote_host'] == '192.0.2.9:61000'
        monkeypatch.setattr(vpn, 'run', lambda args, **k: 'garbage')
        got = c.get(f'/api/connections/{i}').json()
        assert got['site_a']['status'] == 'unknown'
    finally:
        monkeypatch.setenv('VPNAAS_DRY_RUN', '1')
        c.delete(f'/api/connections/{i}')


def test_revoke_terminates_only_own_hub_sas(monkeypatch):
    import subprocess
    seen = []

    class R:
        returncode = 0
        stdout = ''
        stderr = ''
    monkeypatch.delenv('VPNAAS_DRY_RUN')
    monkeypatch.setattr(subprocess, 'run', lambda args, **k: seen.append(args) or R())
    try:
        vpn.revoke('connections', 40, row=HUB)
    finally:
        monkeypatch.setenv('VPNAAS_DRY_RUN', '1')
    names = [a[3] for a in seen]
    assert names == ['hub-40-a', 'hub-40-b']
