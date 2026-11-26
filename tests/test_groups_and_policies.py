"""C2S Groups, C2S->Site access, and Granular Firewall Policies (ports, priority, deny)."""
from test_api import TestClient
from app import app
import vpn

H = {'X-API-Key': 'test-key'}


def client():
    return TestClient(app, headers=H)


def test_groups_and_c2s_to_site_access():
    c = client()
    site = c.post('/api/sites', json={'name': 'dc-bandung', 'subnets': '10.88.0.0/24'}).json()
    grp = c.post('/api/groups', json={
        'name': 'devops',
        'description': 'DevOps team access',
        'allowed_cidrs': ['10.10.7.0/24'],
        'allowed_sites': [site['id']],
    }).json()
    # User can omit allowed_cidrs when granted via group/site
    user = c.post('/api/users', json={
        'username': 'budi-devops',
        'password': 'safe-password-123',
        'groups': [grp['id']],
    }).json()
    deny_pol = c.post('/api/policies', json={
        'name': 'block-ssh-devops',
        'source_type': 'group',
        'source_ref': grp['id'],
        'destination_type': 'site',
        'destination_ref': site['id'],
        'protocol': 'tcp',
        'ports': '22,23',
        'action': 'deny',
        'priority': 10,
    }).json()
    try:
        assert user['groups'] == [grp['id']] and user['allowed_cidrs'] == []
        # Referential integrity: cannot delete group while user references it
        assert c.delete(f"/api/groups/{grp['id']}").status_code == 409

        from store import rows
        sites, groups, users, policies = rows('sites'), rows('groups'), rows('users'), rows('policies')

        # 1. C2S user local_ts includes BOTH group's VPC CIDR and site's subnet!
        rendered = vpn.render([], users, sites=sites, groups=groups, policies=policies)
        ublock = rendered.split(f"user-{user['id']} {{", 1)[1].split('\n}', 1)[0]
        assert 'local_ts = 10.10.7.0/24,10.88.0.0/24' in ublock

        # 2. Site's Hub local_ts includes the C2S VIP pool so return traffic routes back to C2S client!
        sblock = rendered.split(f"site-n-{site['id']} {{", 1)[1].split('\n}', 1)[0]
        assert '172.31.201.0/24' in sblock

        # 3. Firewall chain users places DENY policy (port 22,23) BEFORE general accept!
        fw = vpn.firewall([], users, policies, sites=sites, groups=groups)
        v = user['virtual_ip']
        deny_rule = f'ip saddr {v} ip daddr 10.88.0.0/24 rt ipsec exists tcp dport {{ 22, 23 }} drop'
        allow_rule = f'ip saddr {v} ip daddr 10.88.0.0/24 rt ipsec exists accept'
        assert deny_rule in fw and allow_rule in fw
        assert fw.index(deny_rule) < fw.index(allow_rule)

        # 4. Profile exposes effective combined allowed_cidrs
        prof = c.get(f"/api/users/{user['id']}/profile").json()
        assert prof['allowed_cidrs'] == ['10.10.7.0/24', '10.88.0.0/24']
    finally:
        c.delete(f"/api/policies/{deny_pol['id']}")
        c.delete(f"/api/users/{user['id']}")
        c.delete(f"/api/groups/{grp['id']}")
        c.delete(f"/api/sites/{site['id']}")


def test_policy_ports_priority_and_validation():
    c = client()
    # Ports rejected for protocol=all or icmp
    assert c.post('/api/policies', json={
        'name': 'bad-ports-all', 'source_cidr': '10.1.0.0/24', 'destination_cidr': '10.2.0.0/24',
        'protocol': 'all', 'ports': '443',
    }).status_code == 422
    assert c.post('/api/policies', json={
        'name': 'bad-port-range', 'source_cidr': '10.1.0.0/24', 'destination_cidr': '10.2.0.0/24',
        'protocol': 'tcp', 'ports': '9000-8000',
    }).status_code == 422

    p_low = c.post('/api/policies', json={
        'name': 'allow-web', 'source_cidr': '10.1.0.0/24', 'destination_cidr': '10.2.0.0/24',
        'protocol': 'tcp', 'ports': '80,443,8000-8080', 'action': 'allow', 'priority': 200,
    }).json()
    p_high = c.post('/api/policies', json={
        'name': 'deny-admin-host', 'source_cidr': '10.1.0.99/32', 'destination_cidr': '10.2.0.0/24',
        'protocol': 'tcp', 'ports': '443', 'action': 'deny', 'priority': 50,
    }).json()
    try:
        # GET detail supported on policies now too
        got = c.get(f"/api/policies/{p_low['id']}").json()
        assert got['ports'] == '80,443,8000-8080' and got['priority'] == 200 and got['action'] == 'allow'

        from store import rows
        fw = vpn.firewall([], [], rows('policies'))
        deny_line = 'ip saddr 10.1.0.99/32 ip daddr 10.2.0.0/24 tcp dport 443 drop'
        allow_line = 'ip saddr 10.1.0.0/24 ip daddr 10.2.0.0/24 tcp dport { 80, 443, 8000-8080 } accept'
        assert deny_line in fw and allow_line in fw
        assert fw.index(deny_line) < fw.index(allow_line)
    finally:
        c.delete(f"/api/policies/{p_low['id']}")
        c.delete(f"/api/policies/{p_high['id']}")
