import ipaddress
import sqlite3
import json
import pytest
from fastapi import HTTPException


def test_allocation_independent_of_large_ids_and_exhaustion(monkeypatch):
    import pool
    monkeypatch.setenv('VPNAAS_POOL_CIDR','172.31.222.0/24')
    users=[{'id':999999,'virtual_ip':'172.31.222.1'}]
    assert pool.allocate(users)=='172.31.222.2'
    users=[{'virtual_ip':str(x)} for x in ipaddress.ip_network('172.31.222.0/24').hosts()]
    with pytest.raises(HTTPException) as e:pool.allocate(users)
    assert e.value.status_code==409


def test_select_pool_conflicts_and_persistence(tmp_path):
    import pool
    path=tmp_path/'backend.env'
    occupied=['172.31.201.0/24','172.31.202.0/23','172.31.204.0/22','172.31.208.0/20','172.31.224.0/20','172.31.240.0/21','172.31.248.0/24','172.31.249.0/24']
    assert pool.ensure(path,occupied)=='172.31.250.0/24'
    assert pool.ensure(path,['172.31.0.0/16'])=='172.31.250.0/24'
    with pytest.raises(ValueError):pool.choose(['172.31.0.0/16'])


def test_migration_persists_and_rejects_duplicate(monkeypatch,tmp_path):
    import pool
    monkeypatch.setenv('VPNAAS_POOL_CIDR','172.31.222.0/24')
    conn=sqlite3.connect(tmp_path/'db')
    conn.execute('CREATE TABLE objects(kind TEXT,id INTEGER PRIMARY KEY,body TEXT)')
    conn.execute('INSERT INTO objects VALUES(?,?,?)',('users',999999,json.dumps({'username':'old','password':'unchanged','traffic_mode':'split','allowed_cidrs':['192.0.2.0/24']})))
    pool.migrate(conn); pool.migrate(conn)
    user=json.loads(conn.execute('SELECT body FROM objects').fetchone()[0])
    assert user['virtual_ip']=='172.31.222.1' and user['password']=='unchanged'
    conn.execute('INSERT INTO objects VALUES(?,?,?)',('users',1000000,json.dumps(user)))
    with pytest.raises(ValueError):pool.migrate(conn)
