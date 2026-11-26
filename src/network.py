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


PUBLIC_ROUTE_TABLE = '188'
PUBLIC_ROUTE_PREF = 250
PUBLIC_ROUTE_PROTO = '188'


def snapshot():
    return json.loads(subprocess.check_output(['ip', '-j', '-4', 'route', 'show', 'table', 'main'], timeout=5))


def _interface_ipv4s(dev):
    try:
        out = json.loads(subprocess.check_output(['ip', '-j', '-4', 'addr', 'show', 'dev', dev], timeout=5))
    except Exception:
        return []
    addrs = []
    for item in out:
        for info in item.get('addr_info', []):
            if info.get('family') == 'inet' and info.get('local'):
                addrs.append(info['local'])
    return addrs


def _ip_rules():
    try:
        return json.loads(subprocess.check_output(['ip', '-j', '-4', 'rule', 'show'], timeout=5))
    except Exception:
        return []


def _is_global_ipv4(val):
    if not val:
        return False
    try:
        addr = ipaddress.IPv4Address(val)
        return addr.is_global and not addr.is_private
    except ValueError:
        return False


def public_interface(routes):
    defaults = [r for r in routes if r.get('dst') == 'default' and r.get('dev')]
    if not defaults:
        return None
    configured = os.environ.get('VPNAAS_PUBLIC_IF', '').strip()
    if configured:
        matched = [r for r in defaults if r.get('dev') == configured]
        if matched:
            return configured
    # Multi-NIC OpenStack/cloud guard: prefer a default route carrying a globally
    # routable IPv4 (prefsrc or gateway) over a lower-metric private NIC default.
    global_defaults = [
        r for r in defaults
        if _is_global_ipv4(r.get('prefsrc')) or _is_global_ipv4(r.get('gateway'))
    ]
    pool = global_defaults or defaults
    return min(pool, key=lambda r: r.get('metric', 0))['dev']


def ensure_public_routing(routes=None):
    """Protect inbound SSH/IKEv2 and outbound internet on multi-NIC VMs (e.g. OpenStack).

    1. Pins replies sourced from the public NIC's IPv4 to table 188 (ip rule pref 250,
       after strongSwan table 220 and before main) so a lower-metric default route on a
       private NIC can never hijack SSH or IPsec handshakes into asymmetric drop.
    2. When another NIC advertises a competing lower/equal-metric default route in table
       main, installs an owned `proto 188` higher-priority default route on the public NIC
       without deleting DHCP/cloud-init routes.
    """
    if os.environ.get('VPNAAS_DRY_RUN') == '1':
        return {'changed': False, 'dry_run': True}
    routes = snapshot() if routes is None else routes
    pub_if = public_interface(routes)
    if not pub_if:
        return {'changed': False, 'reason': 'no_public_interface'}

    # Find the native (non-proto-188) default route on pub_if to get its true gateway/metric.
    pub_native = [
        r for r in routes
        if r.get('dst') == 'default' and r.get('dev') == pub_if and r.get('gateway') and str(r.get('protocol', '')) != PUBLIC_ROUTE_PROTO
    ]
    if not pub_native:
        return {'changed': False, 'public_if': pub_if, 'reason': 'no_public_gateway'}
    best_pub = min(pub_native, key=lambda r: int(r.get('metric', 0)))
    pub_gw = best_pub['gateway']
    pub_metric = int(best_pub.get('metric', 0))

    iface_ips = _interface_ipv4s(pub_if)
    env_bind_ip = os.environ.get('VPNAAS_BIND_IP', '').strip()
    env_pub_ip = os.environ.get('VPNAAS_PUBLIC_IP', '').strip()
    pub_src = None
    if best_pub.get('prefsrc') and (not iface_ips or best_pub['prefsrc'] in iface_ips):
        pub_src = best_pub['prefsrc']
    elif env_bind_ip and env_bind_ip in iface_ips:
        pub_src = env_bind_ip
    elif env_pub_ip and env_pub_ip in iface_ips:
        pub_src = env_pub_ip
    elif iface_ips:
        pub_src = next((ip for ip in iface_ips if _is_global_ipv4(ip)), iface_ips[0])

    changed = False

    # 1. Source policy routing table 188 for pub_src -> ALWAYS reply via pub_if/pub_gw!
    if pub_src:
        for r in routes:
            if r.get('dev') == pub_if and r.get('scope') == 'link' and r.get('dst') and r.get('dst') != 'default':
                subprocess.run(
                    ['ip', '-4', 'route', 'replace', r['dst'], 'dev', pub_if, 'scope', 'link', 'src', pub_src, 'table', PUBLIC_ROUTE_TABLE, 'proto', PUBLIC_ROUTE_PROTO],
                    check=False, capture_output=True, text=True, timeout=8,
                )
        subprocess.run(
            ['ip', '-4', 'route', 'replace', 'default', 'via', pub_gw, 'dev', pub_if, 'src', pub_src, 'table', PUBLIC_ROUTE_TABLE, 'proto', PUBLIC_ROUTE_PROTO],
            check=True, capture_output=True, text=True, timeout=8,
        )
        rules = _ip_rules()
        has_rule = False
        for rule in rules:
            if str(rule.get('table')) == PUBLIC_ROUTE_TABLE and int(rule.get('priority', -1)) == PUBLIC_ROUTE_PREF:
                if rule.get('src') == pub_src and str(rule.get('srclen', 32)) == '32':
                    has_rule = True
                else:
                    subprocess.run(
                        ['ip', '-4', 'rule', 'del', 'pref', str(PUBLIC_ROUTE_PREF), 'table', PUBLIC_ROUTE_TABLE],
                        check=False, capture_output=True, text=True, timeout=8,
                    )
                    changed = True
        if not has_rule:
            subprocess.run(
                ['ip', '-4', 'rule', 'add', 'from', f'{pub_src}/32', 'lookup', PUBLIC_ROUTE_TABLE, 'pref', str(PUBLIC_ROUTE_PREF)],
                check=True, capture_output=True, text=True, timeout=8,
            )
            changed = True

    # 2. Competing private-NIC default route guard in table main (owned proto 188 only).
    other_defaults = [
        r for r in routes
        if r.get('dst') == 'default' and r.get('dev') != pub_if and str(r.get('protocol', '')) != PUBLIC_ROUTE_PROTO
    ]
    existing_owned_defaults = [
        r for r in routes
        if r.get('dst') == 'default' and str(r.get('protocol', '')) == PUBLIC_ROUTE_PROTO
    ]
    need_override = False
    desired_metric = None
    if other_defaults:
        min_other = min(int(r.get('metric', 0)) for r in other_defaults)
        if min_other <= pub_metric and min_other > 1:
            need_override = True
            desired_metric = max(1, min_other - 10)

    if need_override:
        already_ok = any(
            r.get('dev') == pub_if and r.get('gateway') == pub_gw and int(r.get('metric', 0)) == desired_metric
            for r in existing_owned_defaults
        )
        if not already_ok:
            args = ['ip', '-4', 'route', 'replace', 'default', 'via', pub_gw, 'dev', pub_if]
            if pub_src:
                args += ['src', pub_src]
            args += ['metric', str(desired_metric), 'proto', PUBLIC_ROUTE_PROTO]
            subprocess.run(args, check=True, capture_output=True, text=True, timeout=8)
            changed = True
        for r in existing_owned_defaults:
            m = int(r.get('metric', 0))
            if r.get('dev') != pub_if or r.get('gateway') != pub_gw or m != desired_metric:
                del_args = ['ip', '-4', 'route', 'del', 'default']
                if m > 0:
                    del_args += ['metric', str(m)]
                del_args += ['proto', PUBLIC_ROUTE_PROTO]
                subprocess.run(del_args, check=False, capture_output=True, text=True, timeout=8)
                changed = True
    else:
        for r in existing_owned_defaults:
            m = int(r.get('metric', 0))
            del_args = ['ip', '-4', 'route', 'del', 'default']
            if m > 0:
                del_args += ['metric', str(m)]
            del_args += ['proto', PUBLIC_ROUTE_PROTO]
            subprocess.run(del_args, check=False, capture_output=True, text=True, timeout=8)
            changed = True

    return {
        'changed': changed,
        'public_if': pub_if,
        'public_src': pub_src,
        'public_gw': pub_gw,
        'override_metric': desired_metric,
    }


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
    from vpn import CONF, firewall, run, atomic, lan_cidr, render, reload_config
    from store import LAN_PLACEHOLDER, rows
    from pathlib import Path
    with configuration_lock():
        try:
            ensure_public_routing()
        except Exception:
            pass
        conns, users, pols = rows('connections'), rows('users'), rows('policies')
        sites, groups, routes = rows('sites'), rows('groups'), rows('routes')
        # If private NIC was hot-attached after boot (LAN_CIDR placeholder), keep swanctl.conf local_ts in sync too.
        if lan_cidr() == LAN_PLACEHOLDER and (sites or users):
            try:
                rendered = render(conns, users, sites=sites, groups=groups, policies=pols, certs=rows('certs'), routes=routes)
                if not CONF.exists() or CONF.read_text() != rendered:
                    atomic(CONF, rendered)
                    reload_config()
            except Exception:
                pass
        rules = firewall(conns, users, pols, sites=sites, groups=groups, routes=routes)
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
