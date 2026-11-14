from test_api import TestClient
import pytest
import vpn
from runtime import user_runtime


@pytest.mark.parametrize('raw', ['', 'garbage', 'list-sa event {', 'list-sas reply {success=no}'])
def test_unavailable_or_malformed_is_unknown(monkeypatch, raw):
    monkeypatch.delenv('VPNAAS_DRY_RUN')
    monkeypatch.setattr(vpn, 'run', lambda *a, **k: raw)
    row = user_runtime([{'id': 1, 'username': 'alice'}])[1]
    assert row['runtime_status'] == 'Unknown'
    assert row['session_count'] is None


def test_backend_failure_is_unknown(monkeypatch):
    monkeypatch.delenv('VPNAAS_DRY_RUN')
    def fail(*a, **k):
        raise TimeoutError()
    monkeypatch.setattr(vpn, 'run', fail)
    assert user_runtime([{'id': 1, 'username': 'alice'}])[1]['runtime_status'] == 'Unknown'


@pytest.mark.parametrize('ike,child,identity,expected', [
    ('ESTABLISHED', 'INSTALLED', 'alice', 'Active'),
    ('CONNECTING', 'INSTALLED', 'alice', 'Down'),
    ('ESTABLISHED', 'REKEYING', 'alice', 'Down'),
    ('ESTABLISHED', 'INSTALLED', 'not-alice', 'Down'),
])
def test_both_ike_and_child_required_with_exact_identity(monkeypatch, ike, child, identity, expected):
    monkeypatch.delenv('VPNAAS_DRY_RUN')
    raw = 'list-sa event {user-1 {state=%s remote-eap-id=%s child-sas {c2s-1 {state=%s}}}} list-sas reply {}' % (ike, identity, child)
    monkeypatch.setattr(vpn, 'run', lambda *a, **k: raw)
    # Administrative state must never manufacture or hide observed liveness.
    assert user_runtime([{'id': 1, 'username': 'alice', 'enabled': False}])[1]['runtime_status'] == expected


def test_empty_successful_snapshot_is_down(monkeypatch):
    monkeypatch.delenv('VPNAAS_DRY_RUN')
    monkeypatch.setattr(vpn, 'run', lambda *a, **k: 'list-sas reply {}')
    row = user_runtime([{'id': 1, 'username': 'alice'}])[1]
    assert row['runtime_status'] == 'Down'
    assert row['session_count'] == 0
