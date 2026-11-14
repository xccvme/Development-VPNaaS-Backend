"""Phase 1: max_sessions field validation, storage, migration and exposure."""
import json
import sqlite3

import pytest

from test_api import TestClient
from app import app

C = lambda: TestClient(app, headers={'X-API-Key': 'test-key'})


def test_field_default_three_in_create_list_and_detail():
    c = C()
    u = c.post('/api/users', json={'username': 'msf-default', 'password': 'safe-password'})
    assert u.status_code == 200
    u = u.json()
    try:
        assert u['max_sessions'] == 3
        row = next(r for r in c.get('/api/users').json() if r['id'] == u['id'])
        assert row['max_sessions'] == 3 and 'session_count' in row
        d = c.get('/api/users/' + str(u['id']))
        assert d.status_code == 200
        d = d.json()
        assert d['max_sessions'] == 3 and 'session_count' in d and 'runtime_status' in d
        assert 'password' not in d and d['username'] == 'msf-default'
        assert c.get('/api/users/999999999').status_code == 404
    finally:
        c.delete('/api/users/' + str(u['id']))


@pytest.mark.parametrize('value', [1, 2, 3])
def test_field_accepts_one_to_three(value):
    c = C()
    u = c.post('/api/users', json={'username': f'msf-ok-{value}', 'password': 'safe-password', 'max_sessions': value})
    assert u.status_code == 200, u.text
    try:
        assert u.json()['max_sessions'] == value
    finally:
        c.delete('/api/users/' + str(u.json()['id']))


@pytest.mark.parametrize('value', [0, -1, 4, 100, '2', 2.0, 1.5, True, None, [1]])
def test_field_rejects_out_of_range_or_non_integer(value):
    c = C()
    r = c.post('/api/users', json={'username': 'msf-bad', 'password': 'safe-password', 'max_sessions': value})
    assert r.status_code == 422
    assert not any(x['username'] == 'msf-bad' for x in c.get('/api/users').json())


def test_field_put_updates_and_rejects_invalid():
    c = C()
    u = c.post('/api/users', json={'username': 'msf-put', 'password': 'safe-password', 'max_sessions': 1}).json()
    try:
        assert c.put('/api/users/' + str(u['id']), json={'max_sessions': 3}).json()['max_sessions'] == 3
        for bad in (0, -2, 4):
            assert c.put('/api/users/' + str(u['id']), json={'max_sessions': bad}).status_code == 422
        assert c.get('/api/users/' + str(u['id'])).json()['max_sessions'] == 3
        assert c.put('/api/users/' + str(u['id']), json={'enabled': False}).json()['max_sessions'] == 3
        # Full UI form payload shape.
        r = c.put('/api/users/' + str(u['id']), json={'username': 'msf-put', 'password': '', 'enabled': True,
                                                      'allowed_cidrs': ['10.10.7.0/24'], 'traffic_mode': 'split',
                                                      'max_sessions': 2})
        assert r.status_code == 200 and r.json()['max_sessions'] == 2
    finally:
        c.delete('/api/users/' + str(u['id']))


def test_field_migration_defaults_existing_rows(tmp_path):
    import store
    conn = sqlite3.connect(tmp_path / 'legacy.sqlite3')
    conn.execute('CREATE TABLE objects (kind TEXT,id INTEGER PRIMARY KEY AUTOINCREMENT, body TEXT)')
    conn.execute('PRAGMA user_version=1')
    conn.execute("INSERT INTO objects(kind,body) VALUES('users',?)", (json.dumps(
        {'username': 'old', 'password': 'x' * 8, 'enabled': True, 'allowed_cidrs': ['10.10.7.0/24'],
         'traffic_mode': 'split', 'virtual_ip': '172.31.201.9'}),))
    conn.execute("INSERT INTO objects(kind,body) VALUES('users',?)", (json.dumps(
        {'username': 'two', 'password': 'x' * 8, 'enabled': True, 'allowed_cidrs': ['10.10.7.0/24'],
         'traffic_mode': 'full', 'virtual_ip': '172.31.201.10', 'max_sessions': 2}),))
    conn.execute("INSERT INTO objects(kind,body) VALUES('policies',?)", (json.dumps({'name': 'p'}),))
    conn.commit()
    store.migrate(conn); store.migrate(conn)
    a, b, p = [json.loads(x) for (x,) in conn.execute('SELECT body FROM objects ORDER BY id')]
    assert a['max_sessions'] == 3 and a['password'] == 'x' * 8 and a['virtual_ip'] == '172.31.201.9'
    assert b['max_sessions'] == 2 and b['traffic_mode'] == 'full'
    assert 'max_sessions' not in p
    assert conn.execute('PRAGMA user_version').fetchone()[0] >= 2


def test_legacy_v0_migration_still_sets_both_defaults(tmp_path):
    import store
    conn = sqlite3.connect(tmp_path / 'v0.sqlite3')
    conn.execute('CREATE TABLE objects (kind TEXT,id INTEGER PRIMARY KEY AUTOINCREMENT, body TEXT)')
    conn.execute("INSERT INTO objects(kind,body) VALUES('users',?)", (json.dumps(
        {'username': 'old', 'password': 'x' * 8, 'enabled': True, 'allowed_cidrs': ['10.10.7.0/24']}),))
    conn.commit()
    store.migrate(conn)
    u = json.loads(conn.execute('SELECT body FROM objects').fetchone()[0])
    assert u['traffic_mode'] == 'split' and u['max_sessions'] == 3
