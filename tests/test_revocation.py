from test_api import TestClient
from app import app

def test_disabled_user_live_sa_is_revoked(monkeypatch):
 import vpn
 c=TestClient(app,headers={'X-API-Key':'test-key'})
 u=c.post('/api/users',json={'username':'revoke-test','password':'safe-password'}).json()
 called=[]
 monkeypatch.setattr(vpn,'revoke',lambda kind,ident:called.append((kind,ident)))
 c.put('/api/users/'+str(u['id']),json={'enabled':False})
 assert ('users',u['id']) in called
 c.delete('/api/users/'+str(u['id']))
