"""Static routing management for VPNaaS gateway.

Uses dedicated Linux kernel routing protocol `proto 188` so VPNaaS only creates,
updates, and deletes routes it owns without touching system, DHCP, or OpenStack
routes.
"""
import ipaddress
import json
import os
import subprocess

VPNAAS_ROUTE_PROTO = '188'


def _kernel_owned_routes():
    out = subprocess.check_output(
        ['ip', '-j', '-4', 'route', 'show', 'proto', VPNAAS_ROUTE_PROTO],
        timeout=5,
        text=True,
    )
    return json.loads(out) if out.strip() else []


def _route_key(dst: str):
    return str(ipaddress.IPv4Network(dst, strict=False))


def apply_routes(routes: list):
    """Idempotently reconcile enabled VPNaaS static routes into Linux table main."""
    if os.environ.get('VPNAAS_DRY_RUN') == '1':
        return {'applied': 0, 'deleted': 0, 'dry_run': True}

    desired = {}
    for r in routes:
        if not r.get('enabled', True):
            continue
        # Routes tied only to an IPsec site without nexthop/dev are handled by XFRM policies.
        if not r.get('gateway') and not r.get('interface'):
            continue
        desired[(_route_key(r['destination_cidr']), int(r.get('metric', 100)))] = r

    existing = {}
    for item in _kernel_owned_routes():
        if item.get('dst') and item['dst'] != 'default':
            existing[(_route_key(item['dst']), int(item.get('metric', 0)))] = item

    applied = 0
    deleted = 0
    for (dst, metric), r in desired.items():
        args = ['ip', '-4', 'route', 'replace', dst]
        if r.get('gateway'):
            args += ['via', r['gateway']]
        if r.get('interface'):
            args += ['dev', r['interface']]
        args += ['metric', str(metric), 'proto', VPNAAS_ROUTE_PROTO]
        subprocess.run(args, check=True, capture_output=True, text=True, timeout=8)
        applied += 1

    for (dst, old_metric) in existing:
        if (dst, old_metric) not in desired:
            del_args = ['ip', '-4', 'route', 'del', dst]
            if old_metric > 0:
                del_args += ['metric', str(old_metric)]
            del_args += ['proto', VPNAAS_ROUTE_PROTO]
            subprocess.run(
                del_args,
                check=False,
                capture_output=True,
                text=True,
                timeout=8,
            )
            deleted += 1

    return {'applied': applied, 'deleted': deleted, 'dry_run': False}


def live_routes(stored_routes: list):
    """Inspect kernel main routing table and report sync status of configured static routes."""
    kernel_routes = []
    kernel_ok = False
    if os.environ.get('VPNAAS_DRY_RUN') != '1':
        try:
            from network import snapshot
            kernel_routes = snapshot()
            kernel_ok = True
        except Exception:
            kernel_routes = []

    by_dst = {}
    for kr in kernel_routes:
        dst = kr.get('dst')
        if not dst or dst == 'default':
            continue
        try:
            by_dst.setdefault(_route_key(dst), []).append(kr)
        except ValueError:
            continue

    annotated = []
    for r in stored_routes:
        item = dict(r)
        if not r.get('enabled', True):
            item['sync_status'] = 'disabled'
        elif not r.get('gateway') and not r.get('interface'):
            item['sync_status'] = 'ipsec-managed'
        elif not kernel_ok:
            item['sync_status'] = 'unknown'
        else:
            matches = by_dst.get(_route_key(r['destination_cidr']), [])
            matched = any(
                (not r.get('gateway') or m.get('gateway') == r['gateway'])
                and (not r.get('interface') or m.get('dev') == r['interface'])
                for m in matches
            )
            item['sync_status'] = 'applied' if matched else 'missing'
        annotated.append(item)

    return {
        'kernel_available': kernel_ok,
        'static_routes': annotated,
        'kernel_routes': kernel_routes,
    }
