from test_api import TestClient
from app import app

def test_validation_error_never_echoes_credentials():
 c=TestClient(app,headers={'X-API-Key':'test-key'})
 r=c.post('/api/users',json=[{'password':'sensitive-string'}])
 assert r.status_code==422
 assert 'sensitive-string' not in r.text

def test_c2s_plaintext_spoof_cannot_fallthrough_global_policy():
 from vpn import firewall
 text=firewall([],[],[dict(id=1,name='broad',source_cidr='0.0.0.0/0',destination_cidr='0.0.0.0/0',protocol='all',enabled=True)])
 assert 'ip saddr 10.250.0.0/24 drop' in text
 assert text.index('ip saddr 10.250.0.0/24 drop') < text.index('ip saddr 0.0.0.0/0')
