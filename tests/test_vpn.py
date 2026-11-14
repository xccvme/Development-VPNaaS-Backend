from test_api import TestClient
from app import app

def test_render_real_config_and_fixed_ip_firewall():
 from vpn import render,firewall
 users=[dict(id=7,username='alice',password='test-password',enabled=True,allowed_cidrs=['10.10.7.0/24'])]
 text=render([],users)
 assert 'eap-mschapv2' in text
 assert 'eap_id = alice' in text
 assert 'addrs = 10.250.0.8' in text
 assert 'local_ts = 10.10.7.0/24' in text
 rules=firewall([],users,[])
 assert 'ip saddr 10.250.0.8 ip daddr 10.10.7.0/24' in rules
 assert 'snat to 10.10.7.14' in rules
 assert 'policy drop' in rules
 assert 'flush ruleset' not in rules

def test_monitoring_and_profile():
 c=TestClient(app,headers={'X-API-Key':'test-key'})
 for path in ['overview','status','audit']:
  assert c.get('/api/'+path).status_code==200
 r=c.post('/api/users',json={'username':'profile-test','password':'safe-password'}).json()
 p=c.get('/api/users/'+str(r['id'])+'/profile')
 assert p.status_code==200 and p.json()['password']=='safe-password'
 assert 'no-store' in p.headers['cache-control']
 c.delete('/api/users/'+str(r['id']))
