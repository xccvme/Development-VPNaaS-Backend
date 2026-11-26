"""Multi-Site S2S (Site-A, Site-B, ..., Site-N) with default-deny inter-site policy."""
import pytest
from test_api import TestClient
from app import app
import vpn

H = {'X-API-Key': 'test-key'}


def client():
    return TestClient(app, headers=H)


def test_multisite_crud_default_deny_and_policy_enabled_transit():
    c = client()
    sa = c.post('/api/sites', json={
        'name': 'site-jakarta',
        'address': '198.51.100.10',
        'subnets': ['192.168.10.0/24', '192.168.11.0/24'],
    }).json()
    sb = c.post('/api/sites', json={
        'name': 'site-bekasi',
        'address': '%any',
        'subnets': '192.168.20.0/24',
        'ike_proposals': 'aes256-sha384-modp3072',
        'esp_proposals': 'aes256-sha384',
    }).json()
    sc = c.post('/api/sites', json={
        'name': 'site-tangerang',
        'subnets': '192.168.30.0/24',
        'allow_vpc': False,
    }).json()
    pol_id = None
    try:
        assert sa['ike_id'] == 'site-jakarta@vpnaas' and sa['psk_set'] is True and 'psk' not in sa
        assert sb['address'] == '%any' and sb['status'] == 'unknown'
        assert sa['subnets'] == '192.168.10.0/24,192.168.11.0/24'
        # Overlapping subnets across sites rejected
        assert c.post('/api/sites', json={'name': 'overlap', 'subnets': '192.168.10.128/25'}).status_code == 422
        # Weak crypto rejected
        assert c.post('/api/sites', json={'name': 'weak', 'subnets': '192.168.40.0/24', 'ike_proposals': '3des-md5-modp1024'}).status_code == 422

        from store import rows
        sites = rows('sites')
        # WITHOUT inter-site policy: default DENY between Site-A and Site-B!
        rendered_before = vpn.render([], [], sites=sites)
        block_a = rendered_before.split(f"site-n-{sa['id']} {{", 1)[1].split('\n}', 1)[0]
        assert '192.168.20.0/24' not in block_a
        assert '10.10.7.0/24' in block_a  # VPC allowed by allow_vpc=True
        fw_before = vpn.firewall([], [], [], sites=sites)
        assert 'ip saddr 192.168.10.0/24 ip daddr 192.168.20.0/24' not in fw_before
        assert 'ip saddr 192.168.10.0/24 ip daddr 10.10.7.0/24 meta ipsec exists accept' in fw_before
        assert 'ip saddr 10.10.7.0/24 ip daddr 192.168.10.0/24 rt ipsec exists accept' in fw_before
        # site-tangerang has allow_vpc=False -> no VPC forward rules
        assert 'ip saddr 192.168.30.0/24 ip daddr 10.10.7.0/24' not in fw_before

        # Add explicit inter-site policy: Jakarta -> Bekasi TCP 443
        p = c.post('/api/policies', json={
            'name': 'jkt-to-bks-https',
            'source_type': 'site',
            'source_ref': sa['id'],
            'destination_type': 'site',
            'destination_ref': sb['id'],
            'protocol': 'tcp',
            'ports': '443',
            'action': 'allow',
        })
        assert p.status_code == 200, p.text
        pol_id = p.json()['id']

        # Deleting a site referenced by policy is blocked with 409
        assert c.delete(f"/api/sites/{sa['id']}").status_code == 409

        # Now local_ts on both Jakarta and Bekasi include each other's subnets!
        policies = rows('policies')
        rendered_after = vpn.render([], [], sites=sites, policies=policies)
        block_a2 = rendered_after.split(f"site-n-{sa['id']} {{", 1)[1].split('\n}', 1)[0]
        block_b2 = rendered_after.split(f"site-n-{sb['id']} {{", 1)[1].split('\n}', 1)[0]
        assert '192.168.20.0/24' in block_a2
        assert '192.168.10.0/24' in block_b2 and '192.168.11.0/24' in block_b2
        # Tangerang still isolated!
        assert '192.168.30.0/24' not in block_a2

        fw_after = vpn.firewall([], [], policies, sites=sites)
        assert 'ip saddr 192.168.10.0/24 ip daddr 192.168.20.0/24 meta ipsec exists rt ipsec exists tcp dport 443 accept' in fw_after
        assert 'ip saddr 192.168.11.0/24 ip daddr 192.168.20.0/24 meta ipsec exists rt ipsec exists tcp dport 443 accept' in fw_after
        # Reverse direction not allowed by policy
        assert 'ip saddr 192.168.20.0/24 ip daddr 192.168.10.0/24 meta ipsec exists rt ipsec exists tcp dport 443 accept' not in fw_after
    finally:
        if pol_id:
            c.delete(f'/api/policies/{pol_id}')
        for s in (sa, sb, sc):
            c.delete(f"/api/sites/{s['id']}")


def test_multisite_actions_and_runtime(monkeypatch):
    c = client()
    sa = c.post('/api/sites', json={'name': 'act-static', 'address': '198.51.100.33', 'subnets': '192.168.50.0/24'}).json()
    sb = c.post('/api/sites', json={'name': 'act-nat', 'address': '%any', 'subnets': '192.168.51.0/24'}).json()
    calls = []
    try:
        # Connect to %any -> 409
        assert c.post(f"/api/sites/{sb['id']}/connect").status_code == 409
        raw = (
            f"list-sa event {{site-n-{sa['id']} {{uniqueid=77 state=ESTABLISHED established=120 remote-host=198.51.100.33 remote-port=4500 "
            f"child-sas {{site-n-{sa['id']}-net-1 {{name=site-n-{sa['id']}-net state=INSTALLED bytes-in=300 bytes-out=400}}}}}}}}\n"
            'list-sas reply {}'
        )
        monkeypatch.setattr(vpn, 'run', lambda args, **k: calls.append(args) or (raw if '--list-sas' in args else 'ok'))
        monkeypatch.delenv('VPNAAS_DRY_RUN')
        got = c.get(f"/api/sites/{sa['id']}").json()
        assert got['status'] == 'active' and got['bytes_in'] == 300 and got['established_sec'] == 120
        # Connect when already active returns already active without calling initiate
        res = c.post(f"/api/sites/{sa['id']}/connect").json()
        assert res['output'] == 'already active'
        # Disconnect terminates site-n-<id>
        calls.clear()
        assert c.post(f"/api/sites/{sa['id']}/disconnect").status_code == 200
        assert calls == [['swanctl', '--terminate', '--ike', f"site-n-{sa['id']}", '--timeout', '12']]
    finally:
        monkeypatch.setenv('VPNAAS_DRY_RUN', '1')
        c.delete(f"/api/sites/{sa['id']}")
        c.delete(f"/api/sites/{sb['id']}")


def test_incremental_s2s_peering_and_selective_c2s_access():
    """Verify exact incremental workflow:
    1. Connect Site-A first (VPC only)
    2. Add Site-B choosing to peer with Site-A -> symmetric peer_sites, hub_local_ts, bidirectional nft + deny override
    3. Add Site-C isolated (no peering) -> stays default-deny from A & B
    4. C2S users: VPC-only, Site-A-only (no VPC), and VPC + Site-A + Site-B (no Site-C)
    """
    c = client()
    sa = c.post('/api/sites', json={'name': 'inc-site-a', 'subnets': '192.168.101.0/24', 'allow_vpc': True}).json()
    sb = sc = u_vpc = u_sitea = u_combo = deny_pol = None
    try:
        # Day 1: Site-A sees only VPC in hub_local_ts
        assert sa['peer_sites'] == [] and sa['hub_local_ts'] == '10.10.7.0/24'

        # Day 2: Add Site-B peered with Site-A, and Site-C isolated
        sb = c.post('/api/sites', json={
            'name': 'inc-site-b', 'subnets': '192.168.102.0/24', 'allow_vpc': True, 'peer_sites': [sa['id']],
        }).json()
        sc = c.post('/api/sites', json={
            'name': 'inc-site-c', 'subnets': '192.168.103.0/24', 'allow_vpc': False, 'peer_sites': [],
        }).json()

        # Symmetric peering persisted on Site-A too!
        sa_now = c.get(f"/api/sites/{sa['id']}").json()
        assert sb['id'] in sa_now['peer_sites'] and sa['id'] in sb['peer_sites']
        assert '192.168.102.0/24' in sa_now['hub_local_ts'] and '192.168.103.0/24' not in sa_now['hub_local_ts']
        assert '192.168.101.0/24' in sb['hub_local_ts'] and '192.168.103.0/24' not in sb['hub_local_ts']
        assert '192.168.101.0/24' not in sc['hub_local_ts'] and '192.168.102.0/24' not in sc['hub_local_ts']

        # Explicit DENY policy between peered sites (block TCP 22 B->A) overrides general peer allow
        deny_pol = c.post('/api/policies', json={
            'name': 'deny-ssh-b-to-a',
            'source_type': 'site', 'source_ref': sb['id'],
            'destination_type': 'site', 'destination_ref': sa['id'],
            'protocol': 'tcp', 'ports': '22', 'action': 'deny', 'priority': 10,
        }).json()

        from store import rows
        fw = vpn.firewall([], [], rows('policies'), sites=rows('sites'))
        deny_line = 'ip saddr 192.168.102.0/24 ip daddr 192.168.101.0/24 meta ipsec exists rt ipsec exists tcp dport 22 drop'
        allow_ab = 'ip saddr 192.168.101.0/24 ip daddr 192.168.102.0/24 meta ipsec exists rt ipsec exists accept'
        allow_ba = 'ip saddr 192.168.102.0/24 ip daddr 192.168.101.0/24 meta ipsec exists rt ipsec exists accept'
        assert deny_line in fw and allow_ab in fw and allow_ba in fw
        assert fw.index(deny_line) < fw.index(allow_ba)
        assert '192.168.103.0/24' not in fw.split('chain forward')[1]

        # C2S selective access:
        # 1. VPC-only
        u_vpc = c.post('/api/users', json={'username': 'c2s-vpc-only', 'password': 'safe-password-1', 'allowed_cidrs': ['10.10.7.0/24']}).json()
        assert u_vpc['effective_cidrs'] == ['10.10.7.0/24'] and u_vpc['allowed_sites'] == []

        # 2. Site-A-only (NO VPC!)
        u_sitea = c.post('/api/users', json={'username': 'c2s-sitea-only', 'password': 'safe-password-2', 'allowed_cidrs': [], 'allowed_sites': [sa['id']]}).json()
        assert u_sitea['effective_cidrs'] == ['192.168.101.0/24']
        # Site-A hub_local_ts now includes C2S pool 172.31.201.0/24, while Site-B & Site-C do not yet!
        assert '172.31.201.0/24' in c.get(f"/api/sites/{sa['id']}").json()['hub_local_ts']
        assert '172.31.201.0/24' not in c.get(f"/api/sites/{sb['id']}").json()['hub_local_ts']

        # 3. VPC + Site-A + Site-B (no Site-C)
        u_combo = c.post('/api/users', json={'username': 'c2s-combo', 'password': 'safe-password-3', 'allowed_cidrs': ['10.10.7.0/24'], 'allowed_sites': [sa['id'], sb['id']]}).json()
        assert u_combo['effective_cidrs'] == ['10.10.7.0/24', '192.168.101.0/24', '192.168.102.0/24']
        assert '172.31.201.0/24' in c.get(f"/api/sites/{sb['id']}").json()['hub_local_ts']
        assert '172.31.201.0/24' not in c.get(f"/api/sites/{sc['id']}").json()['hub_local_ts']

        # Un-peer from Site-A side -> symmetrically clears Site-B too!
        sa_un = c.put(f"/api/sites/{sa['id']}", json={'peer_sites': []}).json()
        sb_un = c.get(f"/api/sites/{sb['id']}").json()
        assert sa_un['peer_sites'] == [] and sb_un['peer_sites'] == []

        # C2S edit transitions: Site-A-only -> VPC+Site-B -> VPC-only -> reject empty grant
        u_edit = c.put(f"/api/users/{u_sitea['id']}", json={'allowed_cidrs': ['10.10.7.0/24'], 'allowed_sites': [sb['id']]}).json()
        assert u_edit['effective_cidrs'] == ['10.10.7.0/24', '192.168.102.0/24']
        u_edit2 = c.put(f"/api/users/{u_sitea['id']}", json={'allowed_cidrs': [], 'allowed_sites': [sa['id']]}).json()
        assert u_edit2['effective_cidrs'] == ['192.168.101.0/24']
        bad_empty = c.put(f"/api/users/{u_sitea['id']}", json={'allowed_cidrs': [], 'allowed_sites': []})
        assert bad_empty.status_code == 422 and 'Minimal satu tujuan akses' in bad_empty.json()['detail']

        # Disabling Site-A when u_sitea only has Site-A must NOT emit broken empty `local_ts = ` in swanctl.conf!
        c.put(f"/api/sites/{sa['id']}", json={'enabled': False})
        rendered_disabled = vpn.render([], rows('users'), sites=rows('sites'), groups=rows('groups'), policies=rows('policies'), routes=rows('routes'))
        assert 'local_ts = \n' not in rendered_disabled
        assert f"user-{u_sitea['id']} {{" not in rendered_disabled
        assert c.get(f"/api/users/{u_sitea['id']}/profile").status_code == 409
        c.put(f"/api/sites/{sa['id']}", json={'enabled': True})

        # Editing policy from tcp+ports to protocol=all clears ports cleanly!
        p_upd = c.put(f"/api/policies/{deny_pol['id']}", json={'protocol': 'all'})
        assert p_upd.status_code == 200 and 'ports' not in p_upd.json()
    finally:
        if deny_pol:
            c.delete(f"/api/policies/{deny_pol['id']}")
        for u in (u_vpc, u_sitea, u_combo):
            if u:
                c.delete(f"/api/users/{u['id']}")
        for s in (sc, sb, sa):
            if s:
                c.delete(f"/api/sites/{s['id']}")
