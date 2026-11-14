from test_api import TestClient
from app import app
import json


def test_api_lease_survives_update_and_large_global_id(monkeypatch):
    import store
    c=TestClient(app,headers={'X-API-Key':'test-key'})
    store.db.execute("INSERT INTO objects(kind,id,body) VALUES('policies',1000000,?)",(json.dumps({'name':'large-id','source_cidr':'192.0.2.0/24','destination_cidr':'198.51.100.0/24','protocol':'all','enabled':False}),))
    store.db.commit()
    try:
        u=c.post('/api/users',json={'username':'large-id-user','password':'test-only-pass'}).json()
        assert u['id']>1000000 and u['virtual_ip'].startswith('172.31.201.')
        assert c.put('/api/users/'+str(u['id']),json={'enabled':False}).json()['virtual_ip']==u['virtual_ip']
        assert c.get('/api/users/'+str(u['id'])+'/profile').json()['virtual_ip']==u['virtual_ip']
        c.delete('/api/users/'+str(u['id']))
    finally:
        store.db.execute('DELETE FROM objects WHERE id=1000000');store.db.commit()


def test_api_exhaustion_does_not_insert_user(monkeypatch):
    import store, pool
    import ipaddress
    c=TestClient(app,headers={'X-API-Key':'test-key'})
    # Occupied persisted rows exercise the real allocator, no mock allocation.
    ids=[]
    try:
        for host in ipaddress.ip_network('172.31.201.0/24').hosts():
            cur=store.db.execute("INSERT INTO objects(kind,body) VALUES('users',?)",(json.dumps({'username':'capacity-'+str(host),'password':'test-only-pass','enabled':False,'traffic_mode':'split','allowed_cidrs':['192.0.2.0/24'],'virtual_ip':str(host)}),))
            ids.append(cur.lastrowid)
        store.db.commit()
        before=len(store.rows('users'))
        r=c.post('/api/users',json={'username':'one-too-many','password':'test-only-pass'})
        assert r.status_code==409 and len(store.rows('users'))==before
    finally:
        store.db.executemany('DELETE FROM objects WHERE id=?',[(x,) for x in ids]);store.db.commit()
