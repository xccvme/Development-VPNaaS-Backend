import os
os.environ['VPNAAS_API_KEY']='test-key'
os.environ['VPNAAS_DRY_RUN']='1'
os.environ['VPNAAS_DB']=':memory:'
from fastapi.testclient import TestClient

def test_authenticated_health():
    from app import app
    c=TestClient(app)
    assert c.get('/api/health').status_code==401
    assert c.get('/api/health',headers={'X-API-Key':'test-key'}).json()['status']=='ok'
