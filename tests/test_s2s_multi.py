"""S2S local_ts/remote_ts: comma-separated lists of 1..8 IPv4 CIDRs."""
import pytest
from fastapi import HTTPException
from test_api import TestClient
from app import app

BASE=dict(name='multi-site',remote_address='192.0.2.20',remote_id='multi.test',psk='secure-test-secret',enabled=True)

def validate(body):
    from store import validate as v
    return v('connections',dict(BASE,**body))

def test_single_cidr_unchanged():
    d=validate(dict(local_ts='10.10.7.0/24',remote_ts='172.16.1.0/24'))
    assert d['local_ts']=='10.10.7.0/24' and d['remote_ts']=='172.16.1.0/24'

def test_list_normalized_deduped_joined():
    d=validate(dict(local_ts=' 10.1.0.5/24 , 10.1.0.0/24,10.3.0.0/16',remote_ts='10.2.0.0/24,10.2.0.0/24'))
    assert d['local_ts']=='10.1.0.0/24,10.3.0.0/16'
    assert d['remote_ts']=='10.2.0.0/24'

@pytest.mark.parametrize('local,remote',[
    ('10.1.0.0/24','0.0.0.0/0'),
    ('10.1.0.0/24,0.0.0.0/0','10.2.0.0/24'),
    ('','10.2.0.0/24'),
    ('10.1.0.0/24',''),
    ('10.1.0.0/24,','10.2.0.0/24'),
    ('10.1.0.0/24',','.join(f'10.2.{n}.0/24' for n in range(9))),
    ('10.1.0.0/24','10.1.0.128/25'),
    ('10.1.0.0/16,10.5.0.0/24','10.6.0.0/24,10.1.4.0/24'),
    ('10.1.0.0/24','172.31.201.0/25'),
    ('172.31.0.0/16','10.2.0.0/24'),
    ('10.1.0.0/24','not-a-cidr'),
    ('10.1.0.0/24','fd00::/64'),
    ('10.1.0.0/24',['10.2.0.0/24']),
])
def test_rejected(local,remote):
    with pytest.raises(HTTPException) as e:validate(dict(local_ts=local,remote_ts=remote))
    assert e.value.status_code==422

def test_eight_allowed():
    remote=','.join(f'10.2.{n}.0/24' for n in range(8))
    assert validate(dict(local_ts='10.1.0.0/24',remote_ts=remote))['remote_ts']==remote

def test_api_roundtrip_and_partial_put():
    c=TestClient(app,headers={'X-API-Key':'test-key'})
    r=c.post('/api/connections',json=dict(BASE,name='multi-api',local_ts='10.1.0.0/24,10.3.0.0/24',remote_ts='10.2.0.0/24'))
    assert r.status_code==200,r.text
    row=r.json();assert row['local_ts']=='10.1.0.0/24,10.3.0.0/24'
    assert c.put(f"/api/connections/{row['id']}",json={'remote_ts':'10.2.0.0/24,10.1.0.0/24'}).status_code==422
    r=c.put(f"/api/connections/{row['id']}",json={'remote_ts':'10.2.0.0/24,10.4.0.0/24'})
    assert r.status_code==200 and r.json()['remote_ts']=='10.2.0.0/24,10.4.0.0/24'
    got=[x for x in c.get('/api/connections').json() if x['id']==row['id']][0]
    assert got['local_ts']=='10.1.0.0/24,10.3.0.0/24'
    assert c.delete(f"/api/connections/{row['id']}").status_code==200

CONN=dict(id=5,enabled=True,remote_address='192.0.2.20',remote_id='peer',psk='secure-test-secret',
          local_ts='10.1.0.0/24,10.3.0.0/24',remote_ts='10.2.0.0/24,10.4.0.0/24')

def test_render_uses_full_lists():
    from vpn import render
    text=render([CONN],[])
    assert ' local_ts = 10.1.0.0/24,10.3.0.0/24\n' in text
    assert ' remote_ts = 10.2.0.0/24,10.4.0.0/24\n' in text

def test_firewall_every_pair_both_directions():
    from vpn import firewall
    rules=firewall([CONN],[],[])
    fwd=rules.split('chain forward')[1].split('chain nat')[0]
    mss=rules.split('chain mss')[1].split('chain forward')[0]
    for l in ('10.1.0.0/24','10.3.0.0/24'):
        for r in ('10.2.0.0/24','10.4.0.0/24'):
            assert f'ip saddr {r} ip daddr {l} meta ipsec exists accept' in fwd
            assert f'ip saddr {l} ip daddr {r} rt ipsec exists accept' in fwd
            assert f'ip saddr {r} ip daddr {l} meta ipsec exists tcp flags' in mss
            assert f'ip saddr {l} ip daddr {r} rt ipsec exists tcp flags' in mss
    assert fwd.count('meta ipsec exists accept')==4
    assert fwd.count('rt ipsec exists accept')==4
    assert '10.1.0.0/24,' not in rules  # never a raw comma list inside a rule

def test_firewall_single_cidr_byte_identical():
    from vpn import firewall
    c=dict(CONN,local_ts='10.1.0.0/24',remote_ts='10.2.0.0/24')
    rules=firewall([c],[],[])
    assert 'ip saddr 10.2.0.0/24 ip daddr 10.1.0.0/24 meta ipsec exists accept\nip saddr 10.1.0.0/24 ip daddr 10.2.0.0/24 rt ipsec exists accept\n' in rules
