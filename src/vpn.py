"""Only validated database fields reach generated configuration. No shell execution."""
import ipaddress
import os
import pathlib
import re
import subprocess
import tempfile
from fastapi import HTTPException
from store import (
    DEFAULT_ESP_PROPOSALS,
    DEFAULT_IKE_PROPOSALS,
    LAN_PLACEHOLDER,
    effective_user_cidrs,
    effective_user_site_ids,
    rows,
    site_effective_subnets,
    ts_split,
)

CONF = pathlib.Path('/etc/swanctl/conf.d/vpnaas.conf')
PUBLIC_IF = os.environ.get('VPNAAS_PUBLIC_IF', 'ens3')
PUBLIC_IP = os.environ.get('VPNAAS_PUBLIC_IP', '203.0.113.10')
LAN_IF = os.environ.get('VPNAAS_LAN_IF', 'ens8')
LAN_IP = os.environ.get('VPNAAS_LAN_IP', '10.10.7.14')
LAN_CIDR = os.environ.get('VPNAAS_LAN_CIDR', '10.10.7.0/24')

# Full-tunnel users may reach the internet but never these non-public ranges
# (other than their own allowed_cidrs, accepted earlier). Includes the VIP pool.
NON_PUBLIC = '{ 0.0.0.0/8, 10.0.0.0/8, 100.64.0.0/10, 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, 192.0.0.0/24, 192.0.2.0/24, 192.168.0.0/16, 198.18.0.0/15, 198.51.100.0/24, 203.0.113.0/24, 224.0.0.0/3 }'
FULL_MSS = 1300


def public_if():
    return os.environ.get('VPNAAS_PUBLIC_IF', PUBLIC_IF)


def public_ip():
    return os.environ.get('VPNAAS_PUBLIC_IP', PUBLIC_IP)


def lan_if():
    return os.environ.get('VPNAAS_LAN_IF', LAN_IF)


def lan_ip():
    return os.environ.get('VPNAAS_LAN_IP', LAN_IP)


def lan_cidr():
    return os.environ.get('VPNAAS_LAN_CIDR', LAN_CIDR)


def full_dns():
    raw = os.environ.get('VPNAAS_FULL_DNS', '1.1.1.1,8.8.8.8')
    servers = [str(ipaddress.IPv4Address(x.strip())) for x in raw.split(',') if x.strip()]
    if not 0 < len(servers) <= 4:
        raise ValueError('VPNAAS_FULL_DNS must list 1-4 IPv4 addresses')
    return servers


def is_full(user):
    return user.get('traffic_mode', 'split') == 'full'


def run(args, timeout=20, input=None):
    result = subprocess.run(args, input=input, text=True, capture_output=True, timeout=timeout)
    if result.returncode:
        raise RuntimeError('VPN command failed')
    return result.stdout


def _lease(value):
    from pool import network
    if not value:
        raise HTTPException(409, 'User VIP missing; migrate database first')
    addr = ipaddress.IPv4Address(value)
    if addr not in network() or addr in (network().network_address, network().broadcast_address):
        raise HTTPException(409, 'Invalid persisted user VIP')
    return str(addr)


def vip(user):
    return _lease(user.get('virtual_ip'))


def session_vips(user):
    """Primary VIP first, then one extra VIP per additional concurrent session slot."""
    return [vip(user)] + [_lease(v) for v in user.get('extra_virtual_ips', [])]


def pool_names(user):
    return [f"pool-{user['id']}"] + [f"pool-{user['id']}-{n}" for n in range(2, len(session_vips(user)) + 1)]


def is_hub(connection):
    return connection.get('topology') == 'hub'


def hub_children(c):
    """{side letter: (conn name, child name, local_ts on hub, remote_ts on hub)}."""
    a, b = c['site_a']['subnets'], c['site_b']['subnets']
    i = c['id']
    return {'a': (f'hub-{i}-a', f'hub-{i}-a-net', b, a), 'b': (f'hub-{i}-b', f'hub-{i}-b-net', a, b)}


def hub_blocks(c):
    pub = public_ip()
    out = []
    for x, (conn, child, local_ts, remote_ts) in hub_children(c).items():
        site = c['site_' + x]
        out.append(f'''{conn} {{
 version = 2
 local_addrs = {pub}
 remote_addrs = {site['address']}
 proposals = {DEFAULT_IKE_PROPOSALS}
 unique = replace
 encap = yes
 dpd_delay = 30s
 local {{ auth = psk
 id = {pub}
 }}
 remote {{ auth = psk
 id = {site['id']}
 }}
 children {{ {child} {{
 local_ts = {local_ts}
 remote_ts = {remote_ts}
 esp_proposals = {DEFAULT_ESP_PROPOSALS}
 start_action = none
 dpd_action = clear
 }} }}
}}''')
    return out


def _policy_connects_sites(policy, site_a, site_b, routes=None):
    """Return True if an enabled allow policy permits traffic between site_a and site_b (either direction)."""
    if not policy.get('enabled', True) or policy.get('action', 'allow') != 'allow':
        return False
    st, dt = policy.get('source_type', 'cidr'), policy.get('destination_type', 'cidr')
    if st == 'site' and dt == 'site':
        pair = {policy.get('source_ref'), policy.get('destination_ref')}
        return pair == {site_a['id'], site_b['id']}
    a_nets = [ipaddress.IPv4Network(x) for x in site_effective_subnets(site_a, routes or [])]
    b_nets = [ipaddress.IPv4Network(x) for x in site_effective_subnets(site_b, routes or [])]
    src_nets = a_nets if (st == 'site' and policy.get('source_ref') == site_a['id']) else (
        b_nets if (st == 'site' and policy.get('source_ref') == site_b['id']) else (
            [ipaddress.IPv4Network(policy['source_cidr'])] if st == 'cidr' and policy.get('source_cidr') else []
        )
    )
    dst_nets = a_nets if (dt == 'site' and policy.get('destination_ref') == site_a['id']) else (
        b_nets if (dt == 'site' and policy.get('destination_ref') == site_b['id']) else (
            [ipaddress.IPv4Network(policy['destination_cidr'])] if dt == 'cidr' and policy.get('destination_cidr') else []
        )
    )
    ab = any(sn.overlaps(a) for sn in src_nets for a in a_nets) and any(dn.overlaps(b) for dn in dst_nets for b in b_nets)
    ba = any(sn.overlaps(b) for sn in src_nets for b in b_nets) and any(dn.overlaps(a) for dn in dst_nets for a in a_nets)
    return ab or ba


def _sites_are_peered(site_a, site_b):
    """True when site_a and site_b are explicitly linked via peer_sites (symmetric)."""
    if site_a['id'] == site_b['id']:
        return False
    return (site_b['id'] in site_a.get('peer_sites', [])) or (site_a['id'] in site_b.get('peer_sites', []))


def site_local_ts(site, sites=None, users=None, groups=None, policies=None, routes=None):
    """Compute Hub's local_ts for a Multi-Site S2S peer:
    VPC/LAN + local static routes (if allow_vpc) + peered or policy-allowed peer sites + C2S pool (if any C2S user can reach this site).
    """
    from pool import network as pool_network
    sites = sites or []
    users = users or []
    groups = groups or []
    policies = policies or []
    routes = routes or []

    out = []
    my_nets = [ipaddress.IPv4Network(x) for x in site_effective_subnets(site, routes)]

    def add(c):
        if not c:
            return
        try:
            net = ipaddress.IPv4Network(c)
        except ValueError:
            return
        if any(net.overlaps(m) for m in my_nets):
            return
        if str(net) not in out:
            out.append(str(net))

    if site.get('allow_vpc', True):
        lan = lan_cidr()
        if lan and lan != LAN_PLACEHOLDER:
            add(lan)
        for r in routes:
            if r.get('enabled', True) and r.get('site_id') is None and (r.get('gateway') or r.get('interface')):
                add(r.get('destination_cidr'))

    # Inter-site subnets ONLY when explicitly peered via peer_sites OR connected by an enabled allow policy (default deny).
    for other in sites:
        if other['id'] == site['id'] or not other.get('enabled', True):
            continue
        if _sites_are_peered(site, other) or any(_policy_connects_sites(p, site, other, routes=routes) for p in policies):
            for c in site_effective_subnets(other, routes):
                add(c)

    # C2S VIP pool when any enabled user/group/policy grants access to this site.
    c2s_allowed = False
    for u in users:
        if not u.get('enabled', True):
            continue
        if site['id'] in effective_user_site_ids(u, groups):
            c2s_allowed = True
            break
        u_nets = [ipaddress.IPv4Network(c) for c in effective_user_cidrs(u, groups, sites, routes)]
        if any(un.overlaps(mn) for un in u_nets for mn in my_nets):
            c2s_allowed = True
            break
    if not c2s_allowed:
        for p in policies:
            if not p.get('enabled', True) or p.get('action', 'allow') != 'allow':
                continue
            if p.get('source_type') in ('user', 'group') and p.get('destination_type') == 'site' and p.get('destination_ref') == site['id']:
                c2s_allowed = True
                break
    if c2s_allowed:
        add(str(pool_network()))

    if not out:
        out.append(lan_cidr())
    return ','.join(out)


def _site_block(site, local_ts, certs_by_id, remote_ts=None):
    pub = public_ip()
    i = site['id']
    conn = f'site-n-{i}'
    child = f'site-n-{i}-net'
    encap_line = ' encap = yes\n' if site.get('encap', True) else ''
    dpd = site.get('dpd_delay', 30)
    ike_p = site.get('ike_proposals', DEFAULT_IKE_PROPOSALS)
    esp_p = site.get('esp_proposals', DEFAULT_ESP_PROPOSALS)
    if site.get('auth_method', 'psk') == 'pubkey':
        cert = certs_by_id.get(site.get('cert_id')) or {}
        remote_id = cert.get('san') or site['ike_id']
        local_auth = f' local {{ auth = pubkey\n certs = server.pem\n id = {pub}\n }}'
        remote_auth = f' remote {{ auth = pubkey\n id = {remote_id}\n cacerts = ca.pem\n revocation = relaxed\n }}'
    else:
        local_auth = f' local {{ auth = psk\n id = {pub}\n }}'
        remote_auth = f' remote {{ auth = psk\n id = {site["ike_id"]}\n }}'
    return f'''{conn} {{
 version = 2
 local_addrs = {pub}
 remote_addrs = {site['address']}
 proposals = {ike_p}
 unique = replace
{encap_line} dpd_delay = {dpd}s
{local_auth}
{remote_auth}
 children {{ {child} {{
 local_ts = {local_ts}
 remote_ts = {remote_ts or site['subnets']}
 esp_proposals = {esp_p}
 start_action = none
 dpd_action = clear
 }} }}
}}'''


def render(connections, users, sites=None, groups=None, policies=None, certs=None, routes=None):
    pub = public_ip()
    sites = sites or []
    groups = groups or []
    policies = policies or []
    routes = routes or []
    certs_by_id = {c['id']: c for c in (certs or [])}

    lines = ['connections {']
    for c in connections:
        if not c['enabled']:
            continue
        if is_hub(c):
            lines.extend(hub_blocks(c))
            continue
        i = c['id']
        lines.append(f'''site-{i} {{
 version = 2
 local_addrs = {pub}
 remote_addrs = {c['remote_address']}
 proposals = {DEFAULT_IKE_PROPOSALS}
 unique = replace
 dpd_delay = 30s
 local {{ auth = psk
 id = {pub}
 }}
 remote {{ auth = psk
 id = {c['remote_id']}
 }}
 children {{ net-{i} {{
 local_ts = {c['local_ts']}
 remote_ts = {c['remote_ts']}
 esp_proposals = {DEFAULT_ESP_PROPOSALS}
 start_action = none
 dpd_action = clear
 }} }}
}}''')

    for s in sites:
        if not s.get('enabled', True):
            continue
        lts = site_local_ts(s, sites=sites, users=users, groups=groups, policies=policies, routes=routes)
        rts = ','.join(site_effective_subnets(s, routes))
        lines.append(_site_block(s, lts, certs_by_id, remote_ts=rts))

    # strongSwan 6.0.1: ask for EAP identity before selecting a user policy.
    # This candidate MUST never authorize: local MSCHAPv2 cannot grant groups.
    # After authentication, strongSwan rejects it and matches the authenticated
    # EAP identity against the per-user candidates below (including their VIPs).
    enabled_eap = [u for u in users if u['enabled'] and u.get('auth_method', 'eap-mschapv2') == 'eap-mschapv2']
    if enabled_eap:
        lines.append(f'''c2s-eap-discovery {{
 version = 2
 local_addrs = {pub}
 remote_addrs = %any
 proposals = {DEFAULT_IKE_PROPOSALS}
 fragmentation = yes
 send_cert = always
 unique = never
 local {{ auth = pubkey
 certs = server.pem
 id = {pub}
 }}
 remote {{ auth = eap-mschapv2
 eap_id = %any
 id = %any
 groups = vpnaas-no-such-group
 }}
}}''')

    for u in users:
        if not u['enabled']:
            continue
        i = u['id']
        eff_cidrs = effective_user_cidrs(u, groups, sites, routes) if (groups or sites or routes or u.get('groups') or u.get('allowed_sites')) else u['allowed_cidrs']
        if not is_full(u) and not eff_cidrs:
            # Skip split-tunnel conn when all referenced sites/groups are currently disabled to avoid empty local_ts syntax error.
            continue
        local_ts = '0.0.0.0/0' if is_full(u) else ','.join(eff_cidrs)
        auth_method = u.get('auth_method', 'eap-mschapv2')
        if auth_method == 'pubkey':
            cert = certs_by_id.get(u.get('cert_id')) or {}
            client_id = cert.get('san') or u['username']
            remote_block = f''' remote {{ auth = pubkey
 id = {client_id}
 cacerts = ca.pem
 revocation = relaxed
 }}'''
        elif auth_method == 'eap-tls':
            remote_block = f''' remote {{ auth = eap-tls
 eap_id = {u['username']}
 id = %any
 cacerts = ca.pem
 revocation = relaxed
 }}'''
        else:
            remote_block = f''' remote {{ auth = eap-mschapv2
 eap_id = {u['username']}
 id = %any
 }}'''
        lines.append(f'''user-{i} {{
 version = 2
 local_addrs = {pub}
 remote_addrs = %any
 proposals = {DEFAULT_IKE_PROPOSALS}
 pools = {','.join(pool_names(u))}
 fragmentation = yes
 send_cert = always
 unique = never
 dpd_delay = 30s
 local {{ auth = pubkey
 certs = server.pem
 id = {pub}
 }}
{remote_block}
 children {{ c2s-{i} {{
 local_ts = {local_ts}
 remote_ts = dynamic
 esp_proposals = {DEFAULT_ESP_PROPOSALS}
 dpd_action = clear
 }} }}
}}''')

    lines.append('}\npools {')
    for u in users:
        if not u['enabled']:
            continue
        dns = f"\n dns = {','.join(full_dns())}" if is_full(u) else ''
        for name, address in zip(pool_names(u), session_vips(u)):
            lines.append(f"{name} {{ addrs = {address}{dns}\n }}")
    lines.append('}\nsecrets {')
    for c in connections:
        if not c['enabled']:
            continue
        if is_hub(c):
            for x in 'ab':
                site = c['site_' + x]
                lines.append(f'ike-hub-{c["id"]}-{x} {{ id-1 = {pub}\n id-2 = {site["id"]}\n secret = "{site["psk"]}"\n }}')
        else:
            lines.append(f'ike-{c["id"]} {{ id-1 = {pub}\n id-2 = {c["remote_id"]}\n secret = "{c["psk"]}"\n }}')
    for s in sites:
        if s.get('enabled', True) and s.get('auth_method', 'psk') == 'psk':
            lines.append(f'ike-site-n-{s["id"]} {{ id-1 = {pub}\n id-2 = {s["ike_id"]}\n secret = "{s["psk"]}"\n }}')
    for u in users:
        if u['enabled'] and u.get('auth_method', 'eap-mschapv2') == 'eap-mschapv2':
            lines.append(f'eap-{u["id"]} {{ id = {u["username"]}\n secret = "{u["password"]}"\n }}')
    lines.append('}')
    return '\n'.join(lines) + '\n'


def hub_pairs(c):
    """Every (source, destination) CIDR pair of hub transit, A->B then B->A."""
    a, b = ts_split(c['site_a']['subnets']), ts_split(c['site_b']['subnets'])
    return [(x, y) for x in a for y in b] + [(y, x) for x in a for y in b]


def ts_pairs(connection):
    """Every (local, remote) CIDR pair of an S2S connection; legacy rows hold one CIDR each."""
    return [(l, r) for l in ts_split(connection['local_ts']) for r in ts_split(connection['remote_ts'])]


def _proto_port_match(policy):
    proto = policy.get('protocol', 'all')
    ports = policy.get('ports')
    if proto == 'all':
        return ''
    if ports and proto in ('tcp', 'udp'):
        parts = [p.strip() for p in str(ports).split(',') if p.strip()]
        port_expr = parts[0] if len(parts) == 1 else '{ ' + ', '.join(parts) + ' }'
        return f'{proto} dport {port_expr} '
    return f'ip protocol {proto} '


def _resolve_policy_endpoints(policy, users, groups, sites, routes=None):
    """Resolve policy source and destination into (list_of_cidrs, is_c2s_source, is_site_source, is_site_dest)."""
    smap = {s['id']: s for s in sites if s.get('enabled', True)}
    umap = {u['id']: u for u in users if u.get('enabled', True)}
    routes = routes or []
    st = policy.get('source_type', 'cidr')
    dt = policy.get('destination_type', 'cidr')

    is_c2s_src = st in ('user', 'group')
    is_site_src = st == 'site'
    is_site_dst = dt == 'site'

    if st == 'cidr':
        srcs = [policy['source_cidr']] if policy.get('source_cidr') else []
    elif st == 'site':
        s = smap.get(policy.get('source_ref'))
        srcs = site_effective_subnets(s, routes) if s else []
    elif st == 'user':
        u = umap.get(policy.get('source_ref'))
        srcs = session_vips(u) if u else []
    elif st == 'group':
        gid = policy.get('source_ref')
        srcs = [v for u in users if u.get('enabled', True) and gid in u.get('groups', []) for v in session_vips(u)]
    else:
        srcs = []

    if dt == 'cidr':
        dsts = [policy['destination_cidr']] if policy.get('destination_cidr') else []
    elif dt == 'site':
        s = smap.get(policy.get('destination_ref'))
        dsts = site_effective_subnets(s, routes) if s else []
    elif dt == 'vpc':
        lan = lan_cidr()
        dsts = [lan] if lan and lan != LAN_PLACEHOLDER else []
    else:
        dsts = []

    return srcs, dsts, is_c2s_src, is_site_src, is_site_dst


def firewall(connections, users, policies, sites=None, groups=None, routes=None):
    from pool import network
    from network import is_s2s_target, s2s_subnet_networks
    pool = str(network())
    pub_if = public_if()
    pub_ip = public_ip()
    l_if = lan_if()
    l_ip = lan_ip()
    l_cidr = lan_cidr()
    sites = sites or []
    groups = groups or []
    routes = routes or []
    s2s_nets = s2s_subnet_networks(connections, sites, routes=routes)
    local_static_routes = [
        r for r in routes
        if r.get('enabled', True) and r.get('site_id') is None and (r.get('gateway') or r.get('interface'))
    ]

    ordered_policies = sorted(
        [p for p in policies if p.get('enabled', True)],
        key=lambda p: (p.get('priority', 100), p.get('id', 0)),
    )

    # Split C2S-scoped policies (source_type user/group) so they run inside chain users!
    user_deny_rules = []
    user_allow_rules = []
    forward_policies = []
    for p in ordered_policies:
        srcs, dsts, is_c2s_src, is_site_src, is_site_dst = _resolve_policy_endpoints(p, users, groups, sites, routes=routes)
        if not srcs or not dsts:
            continue
        pmatch = _proto_port_match(p)
        verdict = 'drop' if p.get('action', 'allow') == 'deny' else 'accept'
        if is_c2s_src:
            ipsec_out = 'rt ipsec exists ' if is_site_dst else ''
            for src in srcs:
                for dst in dsts:
                    rule = f'ip saddr {src} ip daddr {dst} {ipsec_out}{pmatch}{verdict}'
                    if verdict == 'drop':
                        user_deny_rules.append(rule)
                    else:
                        user_allow_rules.append(rule)
        else:
            forward_policies.append((p, srcs, dsts, is_site_src, is_site_dst, pmatch, verdict))

    lines = ['table inet vpnaas {', 'chain users {']
    # Explicit user/group DENY policies take precedence over general allowed_cidrs.
    lines.extend(user_deny_rules)
    lines.extend(user_allow_rules)

    for u in users:
        if not u['enabled']:
            continue
        eff_cidrs = effective_user_cidrs(u, groups, sites, routes) if (groups or sites or routes or u.get('groups') or u.get('allowed_sites')) else u['allowed_cidrs']
        for v in session_vips(u):
            if is_full(u):
                lines.append(f'ip saddr {v} ip daddr {pool} drop')
            for dest in eff_cidrs:
                if is_s2s_target(dest, s2s_nets):
                    lines.append(f'ip saddr {v} ip daddr {dest} rt ipsec exists accept')
                else:
                    lines.append(f'ip saddr {v} ip daddr {dest} accept')
            if is_full(u):
                lines.append(f'ip saddr {v} ip daddr {NON_PUBLIC} drop')
                lines.append(f'ip saddr {v} oifname "{pub_if}" accept')

    full = [v for u in users if u['enabled'] and is_full(u) for v in session_vips(u)]
    lines += ['drop']
    lines += ['}', 'chain mss { type filter hook forward priority mangle; policy accept;']

    for u in users:
        if not u['enabled']:
            continue
        for v in session_vips(u):
            lines.append(f'ip saddr {v} meta ipsec exists tcp flags & (syn|rst) == syn tcp option maxseg size > {FULL_MSS} tcp option maxseg size set {FULL_MSS}')
            lines.append(f'ip daddr {v} rt ipsec exists tcp flags & (syn|rst) == syn tcp option maxseg size > {FULL_MSS} tcp option maxseg size set {FULL_MSS}')

    for c in connections:
        if not c['enabled']:
            continue
        if is_hub(c):
            for source, dest in hub_pairs(c):
                lines.append(f'ip saddr {source} ip daddr {dest} meta ipsec exists tcp flags & (syn|rst) == syn tcp option maxseg size > {FULL_MSS} tcp option maxseg size set {FULL_MSS}')
            continue
        for local, remote in ts_pairs(c):
            for source, dest, match in ((remote, local, 'meta'), (local, remote, 'rt')):
                lines.append(f'ip saddr {source} ip daddr {dest} {match} ipsec exists tcp flags & (syn|rst) == syn tcp option maxseg size > {FULL_MSS} tcp option maxseg size set {FULL_MSS}')

    # MSS clamping for Multi-Site S2S (Site <-> VPC + local static routes and peered/policy-connected Site <-> Site)
    vpc_and_routes = []
    if l_cidr and l_cidr != LAN_PLACEHOLDER:
        vpc_and_routes.append(l_cidr)
    for r in local_static_routes:
        if r['destination_cidr'] not in vpc_and_routes:
            vpc_and_routes.append(r['destination_cidr'])

    mss_seen = set()
    for s in sites:
        if not s.get('enabled', True):
            continue
        s_nets = site_effective_subnets(s, routes)
        if s.get('allow_vpc', True):
            for local_net in vpc_and_routes:
                for sub in s_nets:
                    for src, dst, match in ((sub, local_net, 'meta'), (local_net, sub, 'rt')):
                        key = (src, dst, match)
                        if key not in mss_seen:
                            mss_seen.add(key)
                            lines.append(f'ip saddr {src} ip daddr {dst} {match} ipsec exists tcp flags & (syn|rst) == syn tcp option maxseg size > {FULL_MSS} tcp option maxseg size set {FULL_MSS}')
        for other in sites:
            if other['id'] <= s['id'] or not other.get('enabled', True):
                continue
            if _sites_are_peered(s, other) or any(_policy_connects_sites(p, s, other, routes=routes) for p in ordered_policies):
                for a_sub in s_nets:
                    for b_sub in site_effective_subnets(other, routes):
                        for src, dst in ((a_sub, b_sub), (b_sub, a_sub)):
                            key = (src, dst, 'meta')
                            if key not in mss_seen:
                                mss_seen.add(key)
                                lines.append(f'ip saddr {src} ip daddr {dst} meta ipsec exists tcp flags & (syn|rst) == syn tcp option maxseg size > {FULL_MSS} tcp option maxseg size set {FULL_MSS}')

    lines += ['}', 'chain forward { type filter hook forward priority 0; policy drop;']
    lines += [
        'ct state established,related accept',
        f'ip saddr {pool} meta ipsec exists jump users',
        f'ip saddr {pool} drop',
    ]

    # Explicit DENY policies run BEFORE peer_sites / allow_vpc / allow policies so granular blocks always win.
    deny_fwd = [item for item in forward_policies if item[6] == 'drop']
    allow_fwd = [item for item in forward_policies if item[6] != 'drop']

    def _emit_fwd(items):
        for _p, srcs, dsts, is_site_src, is_site_dst, pmatch, verdict in items:
            ipsec_guard = ''
            if is_site_src and is_site_dst:
                ipsec_guard = 'meta ipsec exists rt ipsec exists '
            elif is_site_src:
                ipsec_guard = 'meta ipsec exists '
            elif is_site_dst:
                ipsec_guard = 'rt ipsec exists '
            for src in srcs:
                for dst in dsts:
                    lines.append(f'ip saddr {src} ip daddr {dst} {ipsec_guard}{pmatch}{verdict}')

    _emit_fwd(deny_fwd)

    for c in connections:
        if not c['enabled']:
            continue
        if is_hub(c):
            # Transit A<->B: enforce BOTH ingress & egress IPsec so packets cannot leak plaintext if peer leg is down.
            for source, dest in hub_pairs(c):
                lines.append(f'ip saddr {source} ip daddr {dest} meta ipsec exists rt ipsec exists accept')
            continue
        for local, remote in ts_pairs(c):
            lines.append(f'ip saddr {remote} ip daddr {local} meta ipsec exists accept')
            lines.append(f'ip saddr {local} ip daddr {remote} rt ipsec exists accept')

    # Multi-Site S2S <-> VPC/local static routes (if allow_vpc=True) and explicitly peered sites (peer_sites). Non-peered sites stay DEFAULT DENY.
    for s in sites:
        if not s.get('enabled', True):
            continue
        s_nets = site_effective_subnets(s, routes)
        if s.get('allow_vpc', True):
            for local_net in vpc_and_routes:
                for sub in s_nets:
                    lines.append(f'ip saddr {sub} ip daddr {local_net} meta ipsec exists accept')
                    lines.append(f'ip saddr {local_net} ip daddr {sub} rt ipsec exists accept')
        for other in sites:
            if other['id'] <= s['id'] or not other.get('enabled', True):
                continue
            if _sites_are_peered(s, other):
                for a_sub in s_nets:
                    for b_sub in site_effective_subnets(other, routes):
                        lines.append(f'ip saddr {a_sub} ip daddr {b_sub} meta ipsec exists rt ipsec exists accept')
                        lines.append(f'ip saddr {b_sub} ip daddr {a_sub} meta ipsec exists rt ipsec exists accept')

    # Granular ALLOW policies (sorted by priority; C2S pool already intercepted above).
    _emit_fwd(allow_fwd)

    lines += [
        '}',
        'chain nat { type nat hook postrouting priority srcnat; policy accept;',
        f'ip saddr {pool} ip daddr {l_cidr} oifname "{l_if}" snat to {l_ip}',
    ]
    for r in local_static_routes:
        if r['destination_cidr'] != l_cidr:
            out_if = r.get('interface') or l_if
            lines.append(f'ip saddr {pool} ip daddr {r["destination_cidr"]} oifname "{out_if}" snat to {l_ip}')
    lines += [f'ip saddr {v} oifname "{pub_if}" snat to {pub_ip}' for v in full]
    lines += ['}', '}']
    text = '\n'.join(lines) + '\n'
    if os.environ.get('VPNAAS_ROUTE_AUTO') == '1':
        from network import route_firewall
        text = route_firewall(text, users, connections=connections, sites=sites, groups=groups, routes=routes)
    return text


def atomic(path, text):
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(dir=path.parent)
    try:
        try:
            os.fchmod(fd, 0o600)
        except (AttributeError, OSError):
            pass
        with os.fdopen(fd, 'w') as f:
            f.write(text)
        os.replace(name, path)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def vici_session():
    import vici
    return vici.Session()


OWNED = re.compile(r'(user|site)-\d+|site-n-\d+|hub-\d+-[ab]')


def reload_config():
    # Replacing existing VICI entries preserves insertion order. Unload owned
    # configs (NOT SAs) so discovery is first even on an already-running daemon.
    session = vici_session()
    for name in session.get_conns().get('conns', []):
        label = name.decode() if isinstance(name, bytes) else name
        if label == 'c2s-eap-discovery' or OWNED.fullmatch(label):
            session.unload_conn({'name': name})
    run(['swanctl', '--load-all', '--clear'])


def apply():
    from network import configuration_lock
    with configuration_lock():
        return _apply_locked()


def _apply_locked():
    connections = rows('connections')
    users = rows('users')
    policies = rows('policies')
    sites = rows('sites')
    groups = rows('groups')
    certs = rows('certs')
    routes = rows('routes')

    text = render(connections, users, sites=sites, groups=groups, policies=policies, certs=certs, routes=routes)
    old = CONF.read_text() if CONF.exists() else 'connections {}\n'
    route_auto = os.environ.get('VPNAAS_ROUTE_AUTO') == '1'
    try:
        from routing import apply_routes
        if route_auto:
            # Apply kernel proto-188 routes first so route_firewall() sees them immediately.
            apply_routes(routes)
        rules = firewall(connections, users, policies, sites=sites, groups=groups, routes=routes)
        # Batch replacement is atomic and touches only our table.
        exists = subprocess.run(['nft', 'list', 'table', 'inet', 'vpnaas'], capture_output=True).returncode == 0
        batch = ('delete table inet vpnaas\n' if exists else '') + rules
        run(['nft', '--check', '-f', '-'], input=batch)
        atomic(CONF, text)
        reload_config()
        run(['nft', '-f', '-'], input=batch)
        atomic(pathlib.Path('/opt/vpnaas/firewall.nft'), rules)
        if not route_auto:
            apply_routes(routes)
    except Exception:
        atomic(CONF, old)
        try:
            reload_config()
        except Exception:
            pass
        raise HTTPException(502, 'VPN configuration apply failed; previous configuration restored')


def revoke(kind, ident, row=None):
    if kind not in ('users', 'connections', 'sites') or os.environ.get('VPNAAS_DRY_RUN') == '1':
        return
    if kind == 'connections' and row and is_hub(row):
        names = [f'hub-{ident}-a', f'hub-{ident}-b']
    elif kind == 'sites':
        names = [f'site-n-{ident}']
    else:
        names = [('user-' if kind == 'users' else 'site-') + str(ident)]
    for name in names:
        # Terminate by exact owned config name; other connections' SAs are untouched.
        # swanctl returns nonzero when no matching SA exists; idempotent revocation.
        result = subprocess.run(['swanctl', '--terminate', '--ike', name, '--timeout', '5'], capture_output=True, text=True, timeout=8)
        if result.returncode and 'no matching' not in (result.stdout + result.stderr).lower():
            raise HTTPException(502, 'Unable to revoke existing VPN session')


def disconnect_user(user, ike_id=None):
    """Explicitly disconnect all sessions of a C2S user or a single numeric ike_id."""
    if os.environ.get('VPNAAS_DRY_RUN') == '1':
        return {'ok': True, 'disconnected': ike_id or f"user-{user['id']}", 'dry_run': True}
    from runtime import user_runtime
    if ike_id is not None:
        if not str(ike_id).isdigit():
            raise HTTPException(422, 'ike_id harus angka')
        rt = user_runtime([user])[user['id']]
        owned_ids = {str(s.get('ike_id')) for s in rt.get('sessions', []) if s.get('ike_id') is not None}
        if str(ike_id) not in owned_ids:
            raise HTTPException(404, 'Sesi IKE tidak ditemukan untuk user ini')
        try:
            from vici_client import terminate_ike
            out = terminate_ike(ike_id=str(ike_id), timeout=10, force=True)
            return {'ok': True, 'disconnected': str(ike_id), 'output': out}
        except Exception:
            raise HTTPException(502, 'VPN action failed; inspect status and strongSwan journal')
    try:
        from vici_client import terminate_ike
        out = terminate_ike(name=f"user-{user['id']}", timeout=10, force=False)
        return {'ok': True, 'disconnected': f"user-{user['id']}", 'output': out}
    except Exception as exc:
        if 'no matching' in str(exc).lower():
            return {'ok': True, 'disconnected': f"user-{user['id']}", 'output': 'no active session'}
        raise HTTPException(502, 'VPN action failed; inspect status and strongSwan journal')


def status():
    from pool import network
    return {
        'pool_cidr': str(network()),
        'raw': run(['swanctl', '--list-sas']),
        'connections': run(['swanctl', '--list-conns']),
        'pools': run(['swanctl', '--list-pools']),
        'backend': 'strongSwan swanctl',
    }


NAT_SITE = 'Site di belakang NAT/IP dinamis: connect dari sisi site (jalankan script Configure)'


def site_action(connection, side, operation):
    if not is_hub(connection):
        raise HTTPException(409, 'Bukan koneksi VPN Hub')
    conn, child, _, _ = hub_children(connection)[side]
    if operation == 'connect':
        if not connection['enabled']:
            raise HTTPException(409, 'Connection disabled')
        if connection['site_' + side]['address'] == '%any':
            raise HTTPException(409, NAT_SITE)
        from runtime import hub_runtime
        if hub_runtime([connection])[connection['id']]['site_' + side]['status'] == 'active':
            return {'ok': True, 'output': 'already active'}
        args = ['swanctl', '--initiate', '--child', child, '--timeout', '12']
    else:
        args = ['swanctl', '--terminate', '--ike', conn, '--timeout', '12']
    try:
        return {'ok': True, 'output': run(args, timeout=18)}
    except Exception:
        raise HTTPException(502, 'VPN action failed; inspect status and strongSwan journal')


def site_n_action(site, operation):
    conn = f"site-n-{site['id']}"
    child = f"site-n-{site['id']}-net"
    if operation == 'connect':
        if not site.get('enabled', True):
            raise HTTPException(409, 'Site disabled')
        if site.get('address') == '%any':
            raise HTTPException(409, NAT_SITE)
        from runtime import site_runtime
        if site_runtime([site])[site['id']]['status'] == 'active':
            return {'ok': True, 'output': 'already active'}
        args = ['swanctl', '--initiate', '--child', child, '--timeout', '12']
    else:
        args = ['swanctl', '--terminate', '--ike', conn, '--timeout', '12']
    try:
        return {'ok': True, 'output': run(args, timeout=18)}
    except Exception:
        raise HTTPException(502, 'VPN action failed; inspect status and strongSwan journal')


def action(connection, operation):
    if is_hub(connection):
        raise HTTPException(409, 'Koneksi VPN Hub: gunakan /sites/{a|b}/connect atau /disconnect')
    if operation == 'initiate':
        if not connection['enabled']:
            raise HTTPException(409, 'Connection disabled')
        args = ['swanctl', '--initiate', '--child', f'net-{connection["id"]}', '--timeout', '12']
    else:
        args = ['swanctl', '--terminate', '--ike', f'site-{connection["id"]}', '--timeout', '12']
    try:
        return {'ok': True, 'output': run(args, timeout=18)}
    except Exception:
        raise HTTPException(502, 'VPN action failed; inspect status and strongSwan journal')
