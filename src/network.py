"""Conservative kernel-route reconciliation and S2S-aware C2S dataplane routing.

No interface or DHCP management; only reconciles owned `table inet vpnaas`.
"""
import ipaddress
import json
import os
import re
import subprocess
import threading
from contextlib import contextmanager

try:
    import fcntl
except ImportError:  # pragma: no cover - non-POSIX dev hosts
    fcntl = None

_LOCAL_APPLY_LOCK = threading.RLock()


@contextmanager
def configuration_lock():
    with _LOCAL_APPLY_LOCK:
        if fcntl is None:
            yield
            return
        lock_path = os.environ.get('VPNAAS_APPLY_LOCK', '/run/vpnaas-apply.lock')
        with open(lock_path, 'a') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            yield


def snapshot():
    return json.loads(subprocess.check_output(['ip', '-j', '-4', 'route', 'show', 'table', 'main'], timeout=5))


def public_interface(routes):
    defaults = [r for r in routes if r.get('dst') == 'default' and r.get('dev')]
    return min(defaults, key=lambda r: r.get('metric', 0))['dev'] if defaults else None


def private_route(cidr, routes, public):
    target = ipaddress.IPv4Network(cidr)
    candidates = []
    for r in routes:
        if r.get('dst', 'default') == 'default':
            continue
        try:
            net = ipaddress.IPv4Network(r['dst'])
        except ValueError:
            continue
        if not net.overlaps(target):
            continue
        dev = r.get('dev')
        if r.get('type', 'unicast') != 'unicast' or not dev or dev == public or dev == 'lo':
            return None
        if not re.fullmatch(r'[A-Za-z0-9_.:-]{1,15}', dev):
            return None
        if target.subnet_of(net):
            candidates.append((net.prefixlen, r.get('metric', 0), dev))
    return sorted(candidates, key=lambda x: (-x[0], x[1]))[0][2] if candidates else None


def s2s_subnet_networks(connections=None, sites=None, routes=None):
    """Return list of IPv4Network objects reachable over enabled S2S IPsec tunnels."""
    from store import site_effective_subnets, ts_split
    nets = []
    for s in (sites or []):
        if not s.get('enabled', True):
            continue
        for c in site_effective_subnets(s, routes if routes is not None else []):
            try:
                nets.append(ipaddress.IPv4Network(c))
            except ValueError:
                pass
    for c in (connections or []):
        if not c.get('enabled', True):
            continue
        if c.get('topology') == 'hub':
            for side in ('site_a', 'site_b'):
                for item in ts_split((c.get(side) or {}).get('subnets', '')):
                    try:
                        nets.append(ipaddress.IPv4Network(item))
                    except ValueError:
                        pass
        else:
            for item in ts_split(c.get('remote_ts', '')):
                try:
                    nets.append(ipaddress.IPv4Network(item))
                except ValueError:
                    pass
    return nets


def is_s2s_target(cidr, s2s_nets):
    if not s2s_nets:
        return False
    target = ipaddress.IPv4Network(cidr)
    return any(target.subnet_of(net) for net in s2s_nets)


def diagnostics(users, connections=None, sites=None, groups=None, routes=None):
    kroutes = snapshot()
    public = public_interface(kroutes)
    s2s_nets = s2s_subnet_networks(connections, sites, routes=routes)
    from store import effective_user_cidrs
    cidrs = sorted({c for u in users if u.get('enabled', True) for c in effective_user_cidrs(u, groups, sites, routes)})
    result = []
    for c in cidrs:
        dev = private_route(c, kroutes, public)
        if dev:
            result.append({'cidr': c, 'interface': dev, 'ready': True, 'via': 'private-nic'})
        elif is_s2s_target(c, s2s_nets):
            result.append({'cidr': c, 'interface': 'ipsec', 'ready': True, 'via': 'ipsec-s2s'})
        else:
            result.append({'cidr': c, 'interface': None, 'ready': False, 'via': None})
    return {
        'public_interface': public,
        'private_routes': result,
        'private_ready': all(x['ready'] for x in result),
        'mode': 'kernel-route-auto',
    }


def route_firewall(text, users, connections=None, sites=None, groups=None, routes=None):
    from vpn import session_vips, public_if
    from pool import network
    from store import effective_user_cidrs
    pool = str(network())
    kroutes = snapshot()
    public = public_interface(kroutes)
    s2s_nets = s2s_subnet_networks(connections, sites, routes=routes)
    text = text.replace(f'oifname "{public_if()}"', f'oifname "{public or "__no_route__"}"')

    # Pre-compute O(1) lookup for C2S user allow rules -> private NIC / IPsec S2S / drop
    grant_map = {}
    for u in users:
        if not u.get('enabled', True):
            continue
        user_cidrs = effective_user_cidrs(u, groups, sites, routes)
        for v in session_vips(u):
            for cidr in user_cidrs:
                dev = private_route(cidr, kroutes, public)
                if dev:
                    entry = (
                        f'ip saddr {v} ip daddr {cidr} oifname "{dev}" accept',
                        f'ip saddr {v} ip daddr {cidr} oifname "{dev}" masquerade',
                    )
                elif is_s2s_target(cidr, s2s_nets):
                    # C2S -> S2S site subnet: accept ONLY when routed into an active IPsec XFRM policy.
                    entry = (
                        f'ip saddr {v} ip daddr {cidr} rt ipsec exists accept',
                        None,
                    )
                else:
                    entry = (
                        f'ip saddr {v} ip daddr {cidr} drop',
                        None,
                    )
                grant_map[f'ip saddr {v} ip daddr {cidr} accept'] = entry
                grant_map[f'ip saddr {v} ip daddr {cidr} rt ipsec exists accept'] = entry

    lines = text.splitlines()
    out = []
    nat = []
    for line in lines:
        if line.startswith(f'ip saddr {pool} ip daddr ') and ' snat to ' in line:
            continue
        if ' snat to ' in line:
            line = line.split(' snat to ')[0] + ' masquerade'
        if line in grant_map:
            replacement, nat_rule = grant_map[line]
            line = replacement
            if nat_rule:
                nat.append(nat_rule)
        out.append(line)
        if line.startswith('chain nat {'):
            out.extend(nat)

    # Recheck every outbound VPN packet before established-flow acceptance:
    # detached private routes must not leak an existing flow via public default.
    established = 'ct state established,related accept'
    if established in out and f'ip saddr {pool} drop' in out:
        out.remove(established)
        idx = out.index(f'ip saddr {pool} drop') + 1
        out.insert(idx, established)
    return '\n'.join(out) + '\n'


def reconcile():
    from vpn import firewall, run, atomic
    from store import rows
    from pathlib import Path
    with configuration_lock():
        rules = firewall(rows('connections'), rows('users'), rows('policies'),
                         sites=rows('sites'), groups=rows('groups'), routes=rows('routes'))
        path = Path('/opt/vpnaas/firewall.nft')
        exists = subprocess.run(['nft', 'list', 'table', 'inet', 'vpnaas'], capture_output=True).returncode == 0
        if exists and path.exists() and path.read_text() == rules:
            return
        batch = ('delete table inet vpnaas\n' if exists else '') + rules
        run(['nft', '--check', '-f', '-'], input=batch)
        run(['nft', '-f', '-'], input=batch)
        atomic(path, rules)


if __name__ == '__main__':
    reconcile()
