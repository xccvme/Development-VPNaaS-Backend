from test_api import TestClient  # initializes isolated test environment
from vpn import render, firewall


def test_identity_request_is_non_authorizing_before_per_user_candidates():
    users = [dict(id=3, username='poc-client', password='test-only-a', enabled=True,
                  allowed_cidrs=['10.10.7.0/24']),
             dict(id=9, username='boss-windows', password='test-only-b', enabled=True,
                  allowed_cidrs=['10.10.7.8/32'])]
    text = render([], users)
    # strongSwan <6.0.2 needs an initial, unfulfillable group constraint to
    # request identity then switch to a candidate bound to authenticated EAP ID.
    assert 'c2s-eap-discovery {' in text
    discovery = text.split('c2s-eap-discovery {', 1)[1].split('user-3 {', 1)[0]
    assert 'eap_id = %any' in discovery
    assert 'groups = vpnaas-no-such-group' in discovery
    assert 'pools =' not in discovery
    assert 'children {' not in discovery
    assert text.index('c2s-eap-discovery {') < text.index('user-3 {')
    assert 'eap_id = poc-client' in text and 'eap_id = boss-windows' in text
    assert 'pools = pool-3' in text and 'pools = pool-9' in text
    assert 'addrs = 10.250.0.4' in text and 'addrs = 10.250.0.10' in text
    assert 'local_ts = 10.10.7.8/32' in text
    rules = firewall([], users, [])
    assert 'ip saddr 10.250.0.10 ip daddr 10.10.7.8/32 accept' in rules
    assert 'ip saddr 10.250.0.10 ip daddr 10.10.7.0/24 accept' not in rules
