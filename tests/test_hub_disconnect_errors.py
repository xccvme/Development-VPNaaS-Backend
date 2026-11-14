from fastapi import HTTPException
import pytest
import vpn


def test_disconnect_failure_is_not_success(monkeypatch):
    monkeypatch.setattr(vpn, 'hub_children', lambda c: {'a': ('hub-77-a', 'hub-77-a-net', [], [])})
    def fail(*args, **kwargs):
        raise RuntimeError('daemon unavailable')
    monkeypatch.setattr(vpn, 'run', fail)
    with pytest.raises(HTTPException) as error:
        vpn.site_action({'topology': 'hub'}, 'a', 'disconnect')
    assert error.value.status_code == 502
