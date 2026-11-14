from test_api import TestClient
from app import app

def test_users_policies_and_validation():
 c=TestClient(app,headers={'X-API-Key':'test-key'})
 r=c.post('/api/users',json={'username':'alice','password':'safe-password','allowed_cidrs':['10.10.7.0/24']})
 assert r.status_code==200
 u=r.json();assert 'password' not in u
 assert c.get('/api/users').json()[0]['allowed_cidrs']==['10.10.7.0/24']
 assert c.put('/api/users/'+str(u['id']),json={'enabled':False}).status_code==200
 assert c.delete('/api/users/'+str(u['id'])).status_code==200
 p=c.post('/api/policies',json={'name':'lan','source_cidr':'10.250.0.0/24','destination_cidr':'10.10.7.0/24'});assert p.status_code==200
 assert c.delete('/api/policies/'+str(p.json()['id'])).status_code==200
 assert c.post('/api/users',json={'username':'evil\n}','password':'safe-password'}).status_code==422
 assert c.post('/api/connections',json={'name':'a','remote_address':'x;touch /tmp/a'}).status_code==422
