from test_api import TestClient
import vpn


def test_reload_unloads_only_owned_configs_before_ordered_load(monkeypatch):
    events = []
    class Session:
        def get_conns(self):
            return {'conns': [b'user-3', b'user-9', b'c2s-eap-discovery', b'foreign']}
        def unload_conn(self, message):
            events.append(('unload', message['name']))
    monkeypatch.setattr(vpn, 'vici_session', lambda: Session(), raising=False)
    monkeypatch.setattr(vpn, 'run', lambda args: events.append(('run', args)))
    vpn.reload_config()
    assert events == [('unload', b'user-3'), ('unload', b'user-9'),
                      ('unload', b'c2s-eap-discovery'),
                      ('run', ['swanctl', '--load-all', '--clear'])]
