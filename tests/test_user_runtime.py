from test_api import TestClient
from app import app
import vpn


def test_users_report_real_established_installed_sessions(monkeypatch):
    client = TestClient(app, headers={'X-API-Key': 'test-key'})
    user = client.post('/api/users', json={'username': 'runtime-alice', 'password': 'safe-password'}).json()
    raw = '''list-sa event {user-99 {uniqueid=17 state=ESTABLISHED remote-eap-id=runtime-alice remote-host=192.0.2.8 remote-vips=[172.31.201.9] child-sas {c2s-99 {uniqueid=22 state=INSTALLED bytes-in=1024 bytes-out=2048}}}}
list-sas reply {}'''
    monkeypatch.setattr(vpn, 'run', lambda args, **kwargs: raw)
    monkeypatch.delenv('VPNAAS_DRY_RUN')
    row = next(r for r in client.get('/api/users').json() if r['id'] == user['id'])
    assert row['runtime_status'] == 'Active'
    assert row['session_count'] == 1
    assert row['virtual_ips'] == ['172.31.201.9']
    assert row['sessions'][0]['ike_id'] == '17'
    assert row['sessions'][0]['remote_address'] == '192.0.2.8'
    assert row['sessions'][0]['children'][0]['bytes_in'] == 1024
    assert 'password' not in row
    monkeypatch.setenv('VPNAAS_DRY_RUN', '1')
    client.delete('/api/users/' + str(user['id']))
