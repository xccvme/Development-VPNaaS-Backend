from test_api import TestClient
from app import app

def test_connection_crud_and_secret_redaction():
    c=TestClient(app,headers={'X-API-Key':'test-key'})
    r=c.post('/api/connections',json=dict(name='test-site',remote_address='172.16.1.104',remote_id='client.test',local_ts='10.10.7.0/24',remote_ts='172.16.1.0/24',psk='secure-test-secret',enabled=True))
    assert r.status_code==200
    row=r.json(); assert 'psk' not in row
    assert any(x['id']==row['id'] for x in c.get('/api/connections').json())
    assert c.put('/api/connections/'+str(row['id']),json={'enabled':False}).json()['enabled'] is False
    assert c.delete('/api/connections/'+str(row['id'])).status_code==200
