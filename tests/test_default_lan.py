"""Default allowed_cidrs when the private NIC was attached after install."""
import pytest
from fastapi import HTTPException

import store

ROUTES = [
    {'dst': 'default', 'dev': 'ens3', 'metric': 1002},
    {'dst': 'default', 'dev': 'ens8', 'metric': 1024},
    {'dst': '198.51.100.0/24', 'dev': 'ens3', 'protocol': 'kernel'},
    {'dst': '172.17.0.0/16', 'dev': 'docker0', 'protocol': 'kernel', 'flags': ['linkdown']},
    {'dst': '172.16.50.0/24', 'dev': 'ens8', 'protocol': 'kernel'},
    {'dst': '172.16.50.1', 'dev': 'ens8', 'protocol': 'dhcp'},
]


def use(monkeypatch, routes, lan):
    import network
    monkeypatch.setattr(network, 'snapshot', lambda: routes)
    if lan is None:
        monkeypatch.delenv('VPNAAS_LAN_CIDR', raising=False)
    else:
        monkeypatch.setenv('VPNAAS_LAN_CIDR', lan)


def test_configured_lan_wins(monkeypatch):
    use(monkeypatch, ROUTES, '10.20.0.0/24')
    assert store.default_lan_cidrs() == ['10.20.0.0/24']


def test_placeholder_uses_late_attached_private_nic(monkeypatch):
    use(monkeypatch, ROUTES, '192.0.2.0/24')
    assert store.default_lan_cidrs() == ['172.16.50.0/24']


def test_placeholder_without_private_nic_is_rejected(monkeypatch):
    use(monkeypatch, ROUTES[:4], '192.0.2.0/24')
    with pytest.raises(HTTPException) as e:
        store.default_lan_cidrs()
    assert e.value.status_code == 422


def test_explicit_cidrs_bypass_detection(monkeypatch):
    use(monkeypatch, [], '192.0.2.0/24')
    from test_api import TestClient
    from app import app
    c = TestClient(app, headers={'X-API-Key': 'test-key'})
    r = c.post('/api/users', json={'username': 'lan-explicit', 'password': 'safe-password', 'allowed_cidrs': ['10.9.0.0/24']})
    assert r.status_code == 200, r.text
    try:
        assert r.json()['allowed_cidrs'] == ['10.9.0.0/24']
    finally:
        c.delete('/api/users/' + str(r.json()['id']))
