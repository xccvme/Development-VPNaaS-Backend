"""Per-account concurrent session limit (max_sessions) contract and enforcer."""
import asyncio
import contextlib
import json
import os
import sqlite3

import pytest

from test_api import TestClient
from app import app
import vpn

C = lambda: TestClient(app, headers={'X-API-Key': 'test-key'})


@contextlib.contextmanager
def _dry():
    old = os.environ.get('VPNAAS_DRY_RUN')
    os.environ['VPNAAS_DRY_RUN'] = '1'
    try:
        yield
    finally:
        if old is None:
            os.environ.pop('VPNAAS_DRY_RUN')
        else:
            os.environ['VPNAAS_DRY_RUN'] = old


def _cleanup(c, *ids):
    with _dry():
        for i in ids:
            c.delete('/api/users/' + str(i))


# ---------- model / API ----------

def test_default_three_exposed_in_list_and_detail():
    c = C()
    u = c.post('/api/users', json={'username': 'ms-default', 'password': 'safe-password'})
    assert u.status_code == 200
    u = u.json()
    try:
        assert u['max_sessions'] == 3
        assert len(u['extra_virtual_ips']) == 2 and u['virtual_ip'] not in u['extra_virtual_ips']
        row = next(r for r in c.get('/api/users').json() if r['id'] == u['id'])
        assert row['max_sessions'] == 3 and 'session_count' in row
        d = c.get('/api/users/' + str(u['id']))
        assert d.status_code == 200
        d = d.json()
        assert d['max_sessions'] == 3 and 'session_count' in d and 'runtime_status' in d
        assert 'password' not in d
        assert c.get('/api/users/999999999').status_code == 404
    finally:
        _cleanup(c, u['id'])


@pytest.mark.parametrize('value', [1, 2, 3])
def test_accepts_one_to_three(value):
    c = C()
    u = c.post('/api/users', json={'username': f'ms-ok-{value}', 'password': 'safe-password', 'max_sessions': value})
    assert u.status_code == 200, u.text
    u = u.json()
    try:
        assert u['max_sessions'] == value and len(u['extra_virtual_ips']) == value - 1
    finally:
        _cleanup(c, u['id'])


@pytest.mark.parametrize('value', [0, -1, 4, 100, '2', 2.0, 1.5, True, None, [1]])
def test_rejects_out_of_range_or_non_integer(value):
    c = C()
    r = c.post('/api/users', json={'username': 'ms-bad', 'password': 'safe-password', 'max_sessions': value})
    assert r.status_code == 422
    assert not any(x['username'] == 'ms-bad' for x in c.get('/api/users').json())


def test_put_changes_limit_and_resizes_extra_vips():
    c = C()
    u = c.post('/api/users', json={'username': 'ms-put', 'password': 'safe-password', 'max_sessions': 1}).json()
    try:
        assert u['extra_virtual_ips'] == []
        r = c.put('/api/users/' + str(u['id']), json={'max_sessions': 3}).json()
        assert r['max_sessions'] == 3 and len(r['extra_virtual_ips']) == 2
        assert r['virtual_ip'] == u['virtual_ip']
        keep = r['extra_virtual_ips'][0]
        r = c.put('/api/users/' + str(u['id']), json={'max_sessions': 2}).json()
        assert r['extra_virtual_ips'] == [keep]
        assert c.put('/api/users/' + str(u['id']), json={'max_sessions': 0}).status_code == 422
        assert c.put('/api/users/' + str(u['id']), json={'max_sessions': 4}).status_code == 422
        assert c.put('/api/users/' + str(u['id']), json={'extra_virtual_ips': []}).status_code == 422
        assert c.get('/api/users/' + str(u['id'])).json()['max_sessions'] == 2
        assert c.put('/api/users/' + str(u['id']), json={'enabled': False}).json()['max_sessions'] == 2
    finally:
        _cleanup(c, u['id'])


def test_extra_vips_never_collide_between_users():
    c = C()
    a = c.post('/api/users', json={'username': 'ms-a', 'password': 'safe-password'}).json()
    b = c.post('/api/users', json={'username': 'ms-b', 'password': 'safe-password'}).json()
    try:
        all_vips = [a['virtual_ip'], *a['extra_virtual_ips'], b['virtual_ip'], *b['extra_virtual_ips']]
        assert len(set(all_vips)) == 6
    finally:
        _cleanup(c, a['id'], b['id'])


def test_migration_defaults_existing_rows_to_three(tmp_path, monkeypatch):
    import store, pool
    monkeypatch.setenv('VPNAAS_POOL_CIDR', '172.31.222.0/24')
    conn = sqlite3.connect(tmp_path / 'legacy.sqlite3')
    conn.execute('CREATE TABLE objects (kind TEXT,id INTEGER PRIMARY KEY AUTOINCREMENT, body TEXT)')
    conn.execute('PRAGMA user_version=1')
    conn.execute("INSERT INTO objects(kind,body) VALUES('users',?)", (json.dumps(
        {'username': 'old', 'password': 'x' * 8, 'enabled': True, 'allowed_cidrs': ['10.10.7.0/24'],
         'traffic_mode': 'split', 'virtual_ip': '172.31.222.9'}),))
    conn.execute("INSERT INTO objects(kind,body) VALUES('policies',?)", (json.dumps({'name': 'p'}),))
    conn.commit()
    store.migrate(conn); pool.migrate(conn)
    store.migrate(conn); pool.migrate(conn)  # idempotent
    u, p = [json.loads(b) for (b,) in conn.execute('SELECT body FROM objects ORDER BY id')]
    assert u['max_sessions'] == 3 and u['virtual_ip'] == '172.31.222.9' and u['password'] == 'x' * 8
    assert u['extra_virtual_ips'] == ['172.31.222.1', '172.31.222.2']
    assert 'max_sessions' not in p
    assert conn.execute('PRAGMA user_version').fetchone()[0] >= 2


def test_migration_clamps_limit_when_pool_cannot_supply_extras(tmp_path, monkeypatch):
    import store, pool, ipaddress
    monkeypatch.setenv('VPNAAS_POOL_CIDR', '172.31.222.0/24')
    conn = sqlite3.connect(tmp_path / 'full.sqlite3')
    conn.execute('CREATE TABLE objects (kind TEXT,id INTEGER PRIMARY KEY AUTOINCREMENT, body TEXT)')
    for host in list(ipaddress.ip_network('172.31.222.0/24').hosts())[:253]:
        conn.execute("INSERT INTO objects(kind,body) VALUES('users',?)", (json.dumps(
            {'username': 'u' + str(host).replace('.', '-'), 'password': 'x' * 8, 'enabled': False,
             'allowed_cidrs': ['10.10.7.0/24'], 'virtual_ip': str(host)}),))
    conn.commit()
    store.migrate(conn); pool.migrate(conn)
    users = [json.loads(b) for (b,) in conn.execute('SELECT body FROM objects ORDER BY id')]
    vips = [v for u in users for v in [u['virtual_ip'], *u['extra_virtual_ips']]]
    assert len(vips) == len(set(vips)) == 254
    assert users[0]['max_sessions'] == 2 and all(u['max_sessions'] == 1 for u in users[1:])


def test_create_rejected_when_pool_cannot_hold_all_session_vips():
    import store, ipaddress
    c = C()
    ids = []
    try:
        for host in list(ipaddress.ip_network('172.31.201.0/24').hosts())[:252]:
            cur = store.db.execute("INSERT INTO objects(kind,body) VALUES('users',?)", (json.dumps(
                {'username': 'cap-' + str(host), 'password': 'test-only-pass', 'enabled': False, 'traffic_mode': 'split',
                 'allowed_cidrs': ['192.0.2.0/24'], 'virtual_ip': str(host), 'max_sessions': 1,
                 'extra_virtual_ips': []}),))
            ids.append(cur.lastrowid)
        store.db.commit()
        before = len(store.rows('users'))
        assert c.post('/api/users', json={'username': 'cap-three', 'password': 'test-only-pass'}).status_code == 409
        assert len(store.rows('users')) == before
        ok = c.post('/api/users', json={'username': 'cap-two', 'password': 'test-only-pass', 'max_sessions': 2})
        assert ok.status_code == 200
        ids.append(ok.json()['id'])
    finally:
        store.db.executemany('DELETE FROM objects WHERE id=?', [(x,) for x in ids]); store.db.commit()


# ---------- rendering ----------

USER = dict(id=7, virtual_ip='172.31.201.8', extra_virtual_ips=['172.31.201.9', '172.31.201.10'], max_sessions=3,
            username='alice', password='test-password', enabled=True, allowed_cidrs=['10.10.7.0/24'])


def test_render_pools_for_every_session_vip_and_no_native_replace():
    text = vpn.render([], [USER])
    block = text.split('user-7 {', 1)[1].split('\n}', 1)[0]
    assert 'pools = pool-7,pool-7-2,pool-7-3' in block
    assert 'unique = never' in block and 'unique = replace' not in text
    assert 'dpd_delay = 30s' in block
    assert 'pool-7 { addrs = 172.31.201.8\n }' in text
    assert 'pool-7-2 { addrs = 172.31.201.9\n }' in text
    assert 'pool-7-3 { addrs = 172.31.201.10\n }' in text
    one = dict(USER, extra_virtual_ips=[], max_sessions=1)
    assert 'pools = pool-7\n' in vpn.render([], [one]) and 'pool-7-2' not in vpn.render([], [one])


def test_firewall_grants_every_session_vip():
    rules = vpn.firewall([], [USER], [])
    for v in ['172.31.201.8', '172.31.201.9', '172.31.201.10']:
        assert f'ip saddr {v} ip daddr 10.10.7.0/24 accept' in rules
    full = dict(USER, traffic_mode='full')
    rules = vpn.firewall([], [full], [])
    for v in ['172.31.201.8', '172.31.201.9', '172.31.201.10']:
        assert f'ip saddr {v} ip daddr 172.31.201.0/24 drop' in rules
        assert f'ip saddr {v} oifname "ens3" snat to 203.0.113.10' in rules


def test_invalid_persisted_extra_vip_is_rejected():
    from fastapi import HTTPException
    with pytest.raises(HTTPException):
        vpn.render([], [dict(USER, extra_virtual_ips=['10.0.0.1'])])


# ---------- enforcement ----------

def sa(name, uid, eap, host, port=4500, est=100, state='ESTABLISHED', child=True):
    kids = f' child-sas {{c-{uid} {{uniqueid={uid}0 state=INSTALLED bytes-in=1 bytes-out=1}}}}' if child else ''
    eap_kv = f' remote-eap-id={eap}' if eap else ''
    return (f'list-sa event {{{name} {{uniqueid={uid} state={state}{eap_kv} remote-host={host} '
            f'remote-port={port} established={est}{kids}}}}}\n')


def raw(*events):
    return ''.join(events) + 'list-sas reply {}\n'


class Recorder:
    def __init__(self, raw_text, fail_terminate=False):
        self.raw, self.calls, self.fail = raw_text, [], fail_terminate

    def __call__(self, args, **kw):
        self.calls.append(args)
        if args[:2] == ['swanctl', '--list-sas']:
            return self.raw
        if self.fail:
            raise RuntimeError('VPN command failed')
        return ''


def terminated(rec):
    return [a[a.index('--ike-id') + 1] for a in rec.calls if '--terminate' in a]


@pytest.fixture
def live(monkeypatch):
    monkeypatch.delenv('VPNAAS_DRY_RUN')
    yield monkeypatch
    monkeypatch.setenv('VPNAAS_DRY_RUN', '1')


def _user(c, name, limit):
    with _dry():
        return c.post('/api/users', json={'username': name, 'password': 'safe-password',
                                          'max_sessions': limit}).json()


def test_enforcer_terminates_newest_surplus_by_numeric_id_keeps_oldest(live):
    import sessions, store
    c = C()
    u = _user(c, 'enf-one', 1)
    other = _user(c, 'enf-other', 1)
    try:
        rec = Recorder(raw(
            sa('site-30', 21, None, '198.51.100.7', est=9000),
            sa(f"user-{u['id']}", 40, 'enf-one', '192.0.2.1', est=300),   # oldest -> keep
            sa(f"user-{u['id']}", 52, 'enf-one', '192.0.2.2', est=20),
            sa(f"user-{u['id']}", 47, 'enf-one', '192.0.2.3', est=60),
            sa(f"user-{other['id']}", 60, 'enf-other', '192.0.2.9', est=5),
        ))
        live.setattr(vpn, 'run', rec)
        before = store.db.execute('SELECT COUNT(*) FROM audit WHERE action=?', ('session_limit',)).fetchone()[0]
        actions = sessions.enforce_once()
        assert sorted(terminated(rec)) == ['47', '52']
        for a in rec.calls:
            if '--terminate' in a:
                assert a[:2] == ['swanctl', '--terminate'] and '--ike' not in a and '--force' in a
        assert {x['ike_id'] for x in actions} == {'47', '52'} and all(x['ok'] for x in actions)
        after = store.db.execute('SELECT resource,resource_id FROM audit WHERE action=? ORDER BY id', ('session_limit',)).fetchall()
        assert len(after) - before == 2 and after[-1] == ('users', u['id'])
    finally:
        _cleanup(c, u['id'], other['id'])


def test_enforcer_counts_only_established_and_respects_higher_limit(live):
    import sessions
    c = C()
    u = _user(c, 'enf-two', 2)
    try:
        rec = Recorder(raw(
            sa(f"user-{u['id']}", 10, 'enf-two', '192.0.2.1', est=500),
            sa(f"user-{u['id']}", 11, 'enf-two', '192.0.2.2', est=400),
            sa('c2s-eap-discovery', 12, 'enf-two', '192.0.2.3', est=0, state='CONNECTING', child=False),
        ))
        live.setattr(vpn, 'run', rec)
        assert sessions.enforce_once() == [] and terminated(rec) == []
        rec.raw = raw(
            sa(f"user-{u['id']}", 10, 'enf-two', '192.0.2.1', est=500),
            sa(f"user-{u['id']}", 11, 'enf-two', '192.0.2.2', est=400),
            sa(f"user-{u['id']}", 13, 'enf-two', '192.0.2.3', est=3),
        )
        sessions.enforce_once()
        assert terminated(rec) == ['13']
    finally:
        _cleanup(c, u['id'])


def test_same_endpoint_overlap_is_one_session(live):
    """Make-before-break reauth/rekey overlap from one endpoint is not a 2nd device."""
    import sessions
    c = C()
    u = _user(c, 'enf-mbb', 1)
    try:
        rec = Recorder(raw(
            sa(f"user-{u['id']}", 30, 'enf-mbb', '192.0.2.1', port=4500, est=7000),
            sa(f"user-{u['id']}", 31, 'enf-mbb', '192.0.2.1', port=4500, est=1),
        ))
        live.setattr(vpn, 'run', rec)
        assert sessions.enforce_once() == [] and terminated(rec) == []
        rec.raw = raw(
            sa(f"user-{u['id']}", 30, 'enf-mbb', '192.0.2.1', port=4500, est=7000),
            sa(f"user-{u['id']}", 31, 'enf-mbb', '192.0.2.1', port=4500, est=1),
            sa(f"user-{u['id']}", 35, 'enf-mbb', '192.0.2.1', port=61000, est=2),  # 2nd device behind same NAT
        )
        sessions.enforce_once()
        assert terminated(rec) == ['35']
    finally:
        _cleanup(c, u['id'])


def test_enforcer_is_dry_run_noop_and_failures_are_non_fatal(monkeypatch):
    import sessions
    calls = []
    monkeypatch.setattr(vpn, 'run', lambda *a, **k: calls.append(a) or '')
    assert sessions.enforce_once() == [] and calls == []  # VPNAAS_DRY_RUN=1
    c = C()
    u = _user(c, 'enf-fail', 1)
    try:
        monkeypatch.delenv('VPNAAS_DRY_RUN')
        rec = Recorder(raw(sa('x', 1, 'enf-fail', '192.0.2.1', est=9), sa('x', 2, 'enf-fail', '192.0.2.2', est=1)),
                       fail_terminate=True)
        monkeypatch.setattr(vpn, 'run', rec)
        actions = sessions.enforce_once()
        assert actions == [{'user_id': u['id'], 'username': 'enf-fail', 'ike_id': '2', 'ok': False}]
        monkeypatch.setattr(vpn, 'run', lambda *a, **k: 'garbage')
        with pytest.raises(ValueError):
            sessions.enforce_once()  # malformed snapshot: never guess, loop logs and continues
    finally:
        monkeypatch.setenv('VPNAAS_DRY_RUN', '1')
        _cleanup(c, u['id'])


def test_background_loop_survives_errors_and_cancels(monkeypatch):
    import sessions
    seen = []

    def boom():
        seen.append(1)
        raise RuntimeError('daemon down')
    monkeypatch.setattr(sessions, 'enforce_once', boom)

    async def main():
        task = asyncio.create_task(sessions.session_limit_loop(0.01))
        await asyncio.sleep(0.08)
        assert not task.done()
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
    asyncio.run(main())
    assert len(seen) >= 2


def test_lifespan_starts_no_enforcer_in_dry_run():
    import sessions
    with TestClient(app, headers={'X-API-Key': 'test-key'}) as c:
        assert c.get('/api/health').json()['status'] == 'ok'
        assert sessions.TASK is None
