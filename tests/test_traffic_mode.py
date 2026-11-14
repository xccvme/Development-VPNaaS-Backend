import json
import sqlite3

import pytest

from test_api import TestClient
from app import app


def client():
    return TestClient(app, headers={'X-API-Key': 'test-key'})


def test_traffic_mode_defaults_to_split_and_full_is_persisted():
    c = client()
    r = c.post('/api/users', json={'username': 'mode-default', 'password': 'test-only-pass'})
    assert r.status_code == 200 and r.json()['traffic_mode'] == 'split'
    split_id = r.json()['id']
    r = c.post('/api/users', json={'username': 'mode-full', 'password': 'test-only-pass', 'traffic_mode': 'full'})
    assert r.status_code == 200, r.text
    u = r.json()
    assert u['traffic_mode'] == 'full'
    listed = {x['id']: x for x in c.get('/api/users').json()}
    assert listed[u['id']]['traffic_mode'] == 'full'
    assert listed[split_id]['traffic_mode'] == 'split'
    # partial update without traffic_mode keeps it
    assert c.put('/api/users/'+str(u['id']), json={'enabled': True}).json()['traffic_mode'] == 'full'
    assert c.put('/api/users/'+str(u['id']), json={'traffic_mode': 'split'}).json()['traffic_mode'] == 'split'
    assert c.put('/api/users/'+str(u['id']), json={'traffic_mode': 'full'}).json()['traffic_mode'] == 'full'
    for bad in ['bogus', '', None, 1, 'FULL']:
        r = c.put('/api/users/'+str(u['id']), json={'traffic_mode': bad})
        assert r.status_code == 422, bad
    c.delete('/api/users/'+str(u['id']))
    c.delete('/api/users/'+str(split_id))


def test_profile_reports_mode_and_dns_for_full_only():
    c = client()
    full = c.post('/api/users', json={'username': 'prof-full', 'password': 'test-only-pass', 'traffic_mode': 'full'}).json()
    split = c.post('/api/users', json={'username': 'prof-split', 'password': 'test-only-pass'}).json()
    pf = c.get('/api/users/'+str(full['id'])+'/profile').json()
    ps = c.get('/api/users/'+str(split['id'])+'/profile').json()
    assert pf['traffic_mode'] == 'full' and pf['dns'] == ['1.1.1.1', '8.8.8.8']
    assert ps['traffic_mode'] == 'split' and 'dns' not in ps
    c.delete('/api/users/'+str(full['id']))
    c.delete('/api/users/'+str(split['id']))


def test_default_route_is_not_an_allowed_cidr():
    c = client()
    r = c.post('/api/users', json={'username': 'route0', 'password': 'test-only-pass', 'allowed_cidrs': ['0.0.0.0/0']})
    assert r.status_code == 422


def test_full_dns_is_configurable_and_validated(monkeypatch):
    import vpn
    monkeypatch.setenv('VPNAAS_FULL_DNS', '9.9.9.9, 1.0.0.1')
    assert vpn.full_dns() == ['9.9.9.9', '1.0.0.1']
    monkeypatch.setenv('VPNAAS_FULL_DNS', '9.9.9.9;evil')
    with pytest.raises(ValueError):
        vpn.full_dns()
    monkeypatch.delenv('VPNAAS_FULL_DNS')
    assert vpn.full_dns() == ['1.1.1.1', '8.8.8.8']


USERS = [dict(id=3, username='poc-client', password='***', enabled=True, allowed_cidrs=['10.10.7.0/24'], traffic_mode='split'),
         dict(id=9, username='boss-windows', password='***', enabled=True, allowed_cidrs=['10.10.7.0/24']),
         dict(id=20, username='roamer', password='***', enabled=True, allowed_cidrs=['10.10.7.42/32'], traffic_mode='full')]


def block(text, name):
    return text.split(name+' {', 1)[1].split('\n}', 1)[0]


def test_render_full_user_uses_default_selector_and_dns_pool():
    from vpn import render
    text = render([], USERS)
    assert text.index('c2s-eap-discovery {') < text.index('user-3 {') < text.index('user-20 {')
    assert 'local_ts = 0.0.0.0/0' in block(text, 'user-20')
    assert 'eap_id = roamer' in block(text, 'user-20')
    assert 'local_ts = 10.10.7.0/24' in block(text, 'user-3')
    assert 'local_ts = 10.10.7.0/24' in block(text, 'user-9')
    assert 'pool-20 { addrs = 10.250.0.21\n dns = 1.1.1.1,8.8.8.8\n }' in text
    # split pools are byte-identical to the pre-change rendering
    assert 'pool-3 { addrs = 10.250.0.4\n }' in text and 'pool-9 { addrs = 10.250.0.10\n }' in text
    assert 'aes256-sha256-modp2048' in block(text, 'user-20') and 'esp_proposals = aes256-sha256' in block(text, 'user-20')


def test_firewall_full_user_gets_internet_snat_but_private_ranges_stay_restricted():
    from vpn import firewall
    rules = firewall([], USERS, [])
    lines = rules.splitlines()
    vip = '10.250.0.21'
    allow = lines.index(f'ip saddr {vip} ip daddr 10.10.7.42/32 accept')
    deny = next(i for i, l in enumerate(lines) if l.startswith(f'ip saddr {vip} ip daddr {{') and l.endswith('drop'))
    inet = lines.index(f'ip saddr {vip} oifname "ens3" accept')
    assert allow < deny < inet
    for private in ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '100.64.0.0/10', '169.254.0.0/16', '224.0.0.0/3']:
        assert private in lines[deny]
    assert f'ip saddr {vip} oifname "ens3" snat to 38.47.77.54' in lines
    # split users unchanged: no internet accept, no ens3 snat
    for split_vip in ['10.250.0.4', '10.250.0.10']:
        assert f'ip saddr {split_vip} ip daddr 10.10.7.0/24 accept' in lines
        assert not any(l.startswith(f'ip saddr {split_vip}') and ('ens3' in l or 'drop' in l) for l in lines)
    assert 'ip saddr 10.250.0.0/24 ip daddr 10.10.7.0/24 oifname "ens8" snat to 10.10.7.14' in lines
    assert 'flush' not in rules
    assert any('maxseg' in l and vip in l for l in lines)
    assert not any('maxseg' in l and '10.250.0.4' in l for l in lines)


def test_firewall_split_only_output_is_unchanged():
    from vpn import firewall
    users = [dict(u, traffic_mode='split') for u in USERS[:2]]
    expected = ('table inet vpnaas {\nchain users {\nip saddr 10.250.0.4 ip daddr 10.10.7.0/24 accept\n'
                'ip saddr 10.250.0.10 ip daddr 10.10.7.0/24 accept\ndrop\n}\n'
                'chain forward { type filter hook forward priority 0; policy drop;\nct state established,related accept\n'
                'ip saddr 10.250.0.0/24 meta ipsec exists jump users\nip saddr 10.250.0.0/24 drop\n}\n'
                'chain nat { type nat hook postrouting priority srcnat; policy accept;\n'
                'ip saddr 10.250.0.0/24 ip daddr 10.10.7.0/24 oifname "ens8" snat to 10.10.7.14\n}\n}\n')
    assert firewall([], users, []) == expected


def test_migration_sets_split_on_legacy_rows(tmp_path):
    from store import migrate
    conn = sqlite3.connect(tmp_path / 'legacy.sqlite3')
    conn.execute('CREATE TABLE objects (kind TEXT,id INTEGER PRIMARY KEY AUTOINCREMENT, body TEXT)')
    conn.execute("INSERT INTO objects(kind,body) VALUES('users',?)", (json.dumps({'username': 'old', 'password': 'x'*8, 'enabled': True, 'allowed_cidrs': ['10.10.7.0/24']}),))
    conn.execute("INSERT INTO objects(kind,body) VALUES('users',?)", (json.dumps({'username': 'f', 'password': 'x'*8, 'enabled': True, 'allowed_cidrs': ['10.10.7.0/24'], 'traffic_mode': 'full'}),))
    conn.execute("INSERT INTO objects(kind,body) VALUES('policies',?)", (json.dumps({'name': 'p'}),))
    conn.commit()
    migrate(conn)
    migrate(conn)  # idempotent
    bodies = [json.loads(b) for (b,) in conn.execute('SELECT body FROM objects ORDER BY id')]
    assert bodies[0]['traffic_mode'] == 'split' and bodies[0]['password'] == 'x'*8
    assert bodies[1]['traffic_mode'] == 'full'
    assert 'traffic_mode' not in bodies[2]
    assert conn.execute('PRAGMA user_version').fetchone()[0] >= 1


def test_full_users_cannot_grant_other_vips_even_with_broad_allowed_cidr():
    from vpn import firewall
    u=dict(USERS[2],allowed_cidrs=['10.0.0.0/8'])
    lines=firewall([],[u],[]).splitlines()
    assert lines.index('ip saddr 10.250.0.21 ip daddr 10.250.0.0/24 drop') < lines.index('ip saddr 10.250.0.21 ip daddr 10.0.0.0/8 accept')
