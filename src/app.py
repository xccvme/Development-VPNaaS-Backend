import ipaddress
import json
import os
import re
import subprocess
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Literal, Optional

from fastapi import Body, Depends, FastAPI, HTTPException, Query
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, PlainTextResponse, Response

from auth import (
    authorize,
    create_token,
    list_tokens,
    require_admin,
    require_operator,
    require_readonly,
    revoke_token,
)
from store import (
    FIPS_PROFILE,
    audit,
    db,
    delete_telemetry,
    detach_site_peers,
    effective_user_cidrs,
    effective_user_site_ids,
    get,
    lock,
    public,
    rows,
    site_effective_subnets,
    sync_site_peers,
    ts_split,
    validate,
    vpc_cidrs,
)

API_VERSION = '2.0.0'
_LOG_REDACT = re.compile(
    r'(?i)(secret|password|psk|x-api-key|authorization|bearer|vpnaas_[A-Za-z0-9_-]+|-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----)(\s*[:=]\s*[^\s,;"]+)?'
)


@asynccontextmanager
async def lifespan(_app):
    import sessions
    sessions.start()
    try:
        yield
    finally:
        await sessions.stop()


_public_docs = os.environ.get('VPNAAS_PUBLIC_DOCS') == '1'
app = FastAPI(
    title='VPNaaS Backend API',
    version=API_VERSION,
    lifespan=lifespan,
    docs_url='/docs' if _public_docs else None,
    redoc_url='/redoc' if _public_docs else None,
    openapi_url='/openapi.json' if _public_docs else None,
)


@app.exception_handler(RequestValidationError)
async def sanitized_validation(request, exc):
    return JSONResponse({'detail': 'Invalid request'}, status_code=422)


def apply_configuration():
    if os.environ.get('VPNAAS_DRY_RUN') != '1':
        from vpn import apply
        apply()


def _check_delete_references(kind: str, ident: int):
    if kind == 'sites':
        for u in rows('users'):
            if ident in u.get('allowed_sites', []):
                raise HTTPException(409, f"Site masih dipakai oleh user '{u['username']}'")
        for g in rows('groups'):
            if ident in g.get('allowed_sites', []):
                raise HTTPException(409, f"Site masih dipakai oleh group '{g['name']}'")
        for r in rows('routes'):
            if r.get('site_id') == ident:
                raise HTTPException(409, f"Site masih dipakai oleh route '{r['name']}'")
        for p in rows('policies'):
            if (p.get('source_type') == 'site' and p.get('source_ref') == ident) or (
                p.get('destination_type') == 'site' and p.get('destination_ref') == ident
            ):
                raise HTTPException(409, f"Site masih dipakai oleh policy '{p['name']}'")
    elif kind == 'groups':
        for u in rows('users'):
            if ident in u.get('groups', []):
                raise HTTPException(409, f"Group masih dipakai oleh user '{u['username']}'")
        for p in rows('policies'):
            if p.get('source_type') == 'group' and p.get('source_ref') == ident:
                raise HTTPException(409, f"Group masih dipakai oleh policy '{p['name']}'")
    elif kind == 'users':
        for p in rows('policies'):
            if p.get('source_type') == 'user' and p.get('source_ref') == ident:
                raise HTTPException(409, f"User masih dipakai oleh policy '{p['name']}'")


def with_connection_runtime(result):
    hubs = [r for r in result if r.get('topology') == 'hub']
    directs = [r for r in result if r.get('topology', 'direct') != 'hub']
    if hubs:
        from runtime import hub_runtime
        rt = hub_runtime(hubs)
        for r in hubs:
            for side in ('site_a', 'site_b'):
                r[side] = dict(r[side], **rt[r['id']][side])
    if directs:
        from runtime import direct_runtime
        drt = direct_runtime(directs)
        for r in directs:
            r.update(drt[r['id']])
    return result


def with_site_runtime(result):
    if not result:
        return result
    from runtime import site_runtime
    from vpn import site_local_ts
    with lock:
        all_sites = rows('sites')
        all_users = rows('users')
        all_groups = rows('groups')
        all_policies = rows('policies')
        all_routes = rows('routes')
    rt_all = site_runtime(all_sites)
    site_by_id = {x['id']: x for x in all_sites}
    out = []
    for s in result:
        lts = site_local_ts(s, sites=all_sites, users=all_users, groups=all_groups, policies=all_policies, routes=all_routes)
        eff_subs = site_effective_subnets(s, all_routes)
        peer_details = []
        for pid in s.get('peer_sites', []):
            peer = site_by_id.get(pid)
            if not peer:
                continue
            prt = rt_all.get(pid) or {}
            peer_details.append({
                'id': pid,
                'name': peer['name'],
                'subnets_list': site_effective_subnets(peer, all_routes),
                'online': prt.get('online'),
                'status': prt.get('status', 'unknown'),
                'last_connected_at': prt.get('last_connected_at'),
            })
        st = rt_all.get(s['id']) or site_runtime([s])[s['id']]
        out.append(dict(
            s,
            subnets_list=ts_split(s.get('subnets', '')),
            effective_subnets=eff_subs,
            hub_local_ts=lts,
            hub_local_ts_list=ts_split(lts),
            peer_site_details=peer_details,
            **st,
        ))
    return out


def _user_access_summary(user, eff_site_ids):
    has_vpc = bool(user.get('allow_vpc'))
    all_sites = bool(user.get('allow_all_sites'))
    has_sites = bool(eff_site_ids or user.get('allowed_sites'))
    has_custom = bool(user.get('allowed_cidrs') or user.get('groups'))
    if all_sites and has_vpc:
        return 'all_sites_and_vpc'
    if all_sites:
        return 'all_sites'
    if has_vpc and has_sites:
        return 'vpc_and_sites'
    if has_vpc:
        return 'vpc_only'
    if has_sites and not has_custom:
        return 'sites_only'
    if has_sites:
        return 'custom_and_sites'
    return 'custom'


def with_user_effective(result):
    if not result:
        return result
    with lock:
        g_rows = rows('groups')
        s_rows = rows('sites')
        r_rows = rows('routes')
    out = []
    for u in result:
        eff_cidrs = effective_user_cidrs(u, g_rows, s_rows, r_rows)
        eff_sites = sorted(effective_user_site_ids(u, g_rows, s_rows))
        out.append(dict(
            u,
            effective_cidrs=eff_cidrs,
            effective_site_ids=eff_sites,
            access_summary=_user_access_summary(u, eff_sites),
        ))
    return out


def decorate(kind, row):
    if kind == 'connections':
        return with_connection_runtime([row])[0]
    if kind == 'sites':
        return with_site_runtime([row])[0]
    if kind == 'users':
        return with_user_effective([row])[0]
    return row


def _snapshot_site_ts():
    """Capture {site_id: (local_ts, effective_subnets)} across enabled sites for targeted SA renegotiation."""
    from vpn import site_local_ts
    all_sites = rows('sites')
    if not all_sites:
        return {}
    all_users = rows('users')
    all_groups = rows('groups')
    all_policies = rows('policies')
    all_routes = rows('routes')
    snap = {}
    for s in all_sites:
        if not s.get('enabled', True):
            continue
        lts = site_local_ts(s, sites=all_sites, users=all_users, groups=all_groups, policies=all_policies, routes=all_routes)
        snap[s['id']] = (lts, tuple(site_effective_subnets(s, all_routes)))
    return snap


def _revoke_changed_sites(before_ts, after_ts, already_revoked=None):
    """Revoke ONLY sites whose Hub local_ts or effective_subnets changed so spokes renegotiate immediately."""
    from vpn import revoke
    revoked = set(already_revoked or ())
    for sid, after_val in after_ts.items():
        if sid in revoked:
            continue
        if sid in before_ts and before_ts[sid] != after_val:
            revoke('sites', sid)
            revoked.add(sid)


def register(kind):
    def listing():
        with lock:
            result = [public(r) for r in rows(kind)]
        if kind == 'connections':
            return with_connection_runtime(result)
        if kind == 'sites':
            return with_site_runtime(result)
        if kind == 'users':
            from runtime import user_runtime
            runtime = user_runtime(result)
            result = [dict(user, **runtime[user['id']]) for user in with_user_effective(result)]
        return result

    def detail(ident: int):
        with lock:
            row = public(get(kind, ident))
        if kind == 'users':
            from runtime import user_runtime
            row = with_user_effective([row])[0]
            return dict(row, **user_runtime([row])[row['id']])
        if kind == 'connections':
            return with_connection_runtime([row])[0]
        if kind == 'sites':
            return with_site_runtime([row])[0]
        return row

    def create(body: dict):
        with lock:
            before_ts = _snapshot_site_ts()
            data = validate(kind, body)
            try:
                cur = db.execute('INSERT INTO objects(kind,body) VALUES(?,?)', (kind, json.dumps(data)))
                ident = cur.lastrowid
                changed_peers = []
                if kind == 'sites' and data.get('peer_sites'):
                    changed_peers = sync_site_peers(ident, data['peer_sites'])
                apply_configuration()
                after_ts = _snapshot_site_ts()
                revoked_sites = set()
                if changed_peers:
                    from vpn import revoke
                    for pid in changed_peers:
                        revoke('sites', pid)
                        revoked_sites.add(pid)
                if kind == 'sites' and data.get('enabled', True):
                    from vpn import revoke
                    for u in rows('users'):
                        if u.get('allow_all_sites'):
                            revoke('users', u['id'])
                if kind == 'routes':
                    from vpn import revoke
                    if data.get('site_id'):
                        revoke('sites', data['site_id'])
                        revoked_sites.add(data['site_id'])
                        g_rows = rows('groups')
                        s_rows = rows('sites')
                        for u in rows('users'):
                            if u.get('allow_all_sites') or data['site_id'] in effective_user_site_ids(u, g_rows, s_rows):
                                revoke('users', u['id'])
                    else:
                        for u in rows('users'):
                            if u.get('enabled', True) and u.get('allow_vpc'):
                                revoke('users', u['id'])
                _revoke_changed_sites(before_ts, after_ts, already_revoked=revoked_sites)
                audit('create', kind, ident)
                db.commit()
                return decorate(kind, public(dict(data, id=ident)))
            except Exception:
                db.rollback()
                raise

    def update(ident: int, body: dict):
        with lock:
            before_ts = _snapshot_site_ts()
            previous = get(kind, ident)
            data = validate(kind, body, previous)
            try:
                db.execute('UPDATE objects SET body=? WHERE id=?', (json.dumps(data), ident))
                changed_peers = []
                if kind == 'sites':
                    changed_peers = sync_site_peers(ident, data.get('peer_sites', []))
                # Apply new config BEFORE revoking SA so failed apply never kills live SAs
                # and revoked sessions cannot race-reconnect using removed credentials.
                apply_configuration()
                after_ts = _snapshot_site_ts()
                from vpn import revoke
                revoked_sites = set()
                if kind in ('users', 'connections', 'sites'):
                    revoke(kind, ident, **({'row': previous} if kind == 'connections' else {}))
                    if kind == 'sites':
                        revoked_sites.add(ident)
                if kind == 'sites':
                    for pid in changed_peers:
                        revoke('sites', pid)
                        revoked_sites.add(pid)
                    if previous.get('subnets') != data.get('subnets') or previous.get('enabled', True) != data.get('enabled', True):
                        g_rows = rows('groups')
                        s_rows = rows('sites')
                        for u in rows('users'):
                            if u.get('allow_all_sites') or ident in effective_user_site_ids(u, g_rows, s_rows):
                                revoke('users', u['id'])
                elif kind == 'groups':
                    for u in rows('users'):
                        if ident in u.get('groups', []):
                            revoke('users', u['id'])
                elif kind == 'routes':
                    affected_sites = {s for s in (previous.get('site_id'), data.get('site_id')) if s is not None}
                    for sid in affected_sites:
                        revoke('sites', sid)
                        revoked_sites.add(sid)
                    local_changed = (previous.get('site_id') is None) or (data.get('site_id') is None)
                    if affected_sites or local_changed:
                        g_rows = rows('groups')
                        s_rows = rows('sites')
                        for u in rows('users'):
                            if (affected_sites and (u.get('allow_all_sites') or (affected_sites & effective_user_site_ids(u, g_rows, s_rows)))) or (
                                local_changed and u.get('enabled', True) and u.get('allow_vpc')
                            ):
                                revoke('users', u['id'])
                _revoke_changed_sites(before_ts, after_ts, already_revoked=revoked_sites)
                audit('update', kind, ident)
                db.commit()
                return decorate(kind, public(dict(data, id=ident)))
            except Exception:
                db.rollback()
                raise

    def delete(ident: int):
        with lock:
            before_ts = _snapshot_site_ts()
            previous = get(kind, ident)
            _check_delete_references(kind, ident)
            try:
                db.execute('DELETE FROM objects WHERE id=?', (ident,))
                if kind in ('sites', 'users'):
                    delete_telemetry(kind, ident)
                changed_peers = []
                if kind == 'sites':
                    changed_peers = detach_site_peers(ident)
                apply_configuration()
                after_ts = _snapshot_site_ts()
                from vpn import revoke
                revoked_sites = set()
                if kind in ('users', 'connections', 'sites'):
                    revoke(kind, ident, **({'row': previous} if kind == 'connections' else {}))
                    if kind == 'sites':
                        revoked_sites.add(ident)
                if kind == 'sites':
                    for u in rows('users'):
                        if u.get('allow_all_sites'):
                            revoke('users', u['id'])
                for pid in changed_peers:
                    revoke('sites', pid)
                    revoked_sites.add(pid)
                if kind == 'routes':
                    if previous.get('site_id'):
                        revoke('sites', previous['site_id'])
                        revoked_sites.add(previous['site_id'])
                        g_rows = rows('groups')
                        s_rows = rows('sites')
                        for u in rows('users'):
                            if u.get('allow_all_sites') or previous['site_id'] in effective_user_site_ids(u, g_rows, s_rows):
                                revoke('users', u['id'])
                    else:
                        for u in rows('users'):
                            if u.get('enabled', True) and u.get('allow_vpc'):
                                revoke('users', u['id'])
                _revoke_changed_sites(before_ts, after_ts, already_revoked=revoked_sites)
                audit('delete', kind, ident)
                db.commit()
                return {'deleted': True}
            except Exception:
                db.rollback()
                raise

    read_deps = [Depends(require_readonly)]
    write_deps = [Depends(require_operator)]
    app.add_api_route('/api/' + kind, listing, methods=['GET'], dependencies=read_deps)
    app.add_api_route('/api/' + kind + '/{ident}', detail, methods=['GET'], dependencies=read_deps)
    app.add_api_route('/api/' + kind, create, methods=['POST'], dependencies=write_deps)
    app.add_api_route('/api/' + kind + '/{ident}', update, methods=['PUT'], dependencies=write_deps)
    app.add_api_route('/api/' + kind + '/{ident}', delete, methods=['DELETE'], dependencies=write_deps)


# Register routes BEFORE generic `/api/routes/{ident}` so `/api/routes/live` takes precedence!
@app.get('/api/routes/live', dependencies=[Depends(require_readonly)])
def routes_live():
    from routing import live_routes
    with lock:
        stored = [public(r) for r in rows('routes')]
    return live_routes(stored)


for _kind in ('connections', 'users', 'policies', 'sites', 'groups', 'routes'):
    register(_kind)


# ---------- System, Readiness, Gateway Metadata & OpenAPI ----------

@app.get('/api/health', dependencies=[Depends(require_readonly)])
def health():
    return {'status': 'ok'}


@app.get('/api/openapi.json', dependencies=[Depends(require_readonly)])
def authenticated_openapi():
    return JSONResponse(app.openapi())


@app.get('/api/ready', dependencies=[Depends(require_readonly)])
def readiness():
    """Deep readiness probe for Customer Portal provisioning (Flow Tahap 7)."""
    checks = {}
    dry_run = os.environ.get('VPNAAS_DRY_RUN') == '1'

    # 1. SQLite check
    try:
        with lock:
            db.execute('SELECT 1').fetchone()
        checks['database'] = {'ok': True}
    except Exception as exc:
        checks['database'] = {'ok': False, 'detail': str(exc)}

    # 2. strongSwan / VICI check
    from vici_client import ping_daemon
    sw_ok, sw_info = ping_daemon()
    checks['strongswan'] = {'ok': sw_ok, 'detail': sw_info}

    # 3. nftables check
    if dry_run:
        checks['firewall'] = {'ok': True, 'detail': 'dry-run'}
    else:
        try:
            r = subprocess.run(['nft', 'list', 'table', 'inet', 'vpnaas'], capture_output=True, text=True, timeout=5)
            checks['firewall'] = {'ok': r.returncode == 0, 'detail': 'table inet vpnaas present' if r.returncode == 0 else 'table missing'}
        except Exception as exc:
            checks['firewall'] = {'ok': False, 'detail': str(exc)}

    # 4. PKI check
    import pki
    srv = pki.server_info()
    ca = pki.ca_info()
    if dry_run and not ca['present']:
        checks['pki'] = {'ok': True, 'detail': 'dry-run'}
    else:
        pki_ok = ca['present'] and srv['present'] and not ca.get('expired', False) and not srv.get('expired', False)
        checks['pki'] = {
            'ok': pki_ok,
            'ca_present': ca['present'],
            'server_present': srv['present'],
            'server_days_remaining': srv.get('days_remaining'),
        }

    all_ok = all(c['ok'] for c in checks.values())
    payload = {'ready': all_ok, 'status': 'READY' if all_ok else 'DEGRADED', 'checks': checks}
    return JSONResponse(payload, status_code=200 if all_ok else 503)


@app.get('/api/gateway', dependencies=[Depends(require_readonly)])
def gateway_metadata():
    """Gateway instance metadata for Customer Portal / Orchestrator integration."""
    from pool import network
    from store import LAN_PLACEHOLDER
    from vpn import bind_ip, lan_cidr, public_if, public_ip
    import pki
    import tuning

    with lock:
        all_routes = rows('routes')
        counts = {k: len(rows(k)) for k in ('sites', 'users', 'groups', 'routes', 'policies', 'certs')}
    detected_vpcs = vpc_cidrs(all_routes)
    effective_lan = detected_vpcs[0] if (lan_cidr() == LAN_PLACEHOLDER and detected_vpcs) else lan_cidr()

    return {
        'api_version': API_VERSION,
        'protocol': 'IPsec/IKEv2',
        'engine': 'strongSwan IKEv2/IPsec',
        'default_traffic_mode': 'split',
        'fips_compliant': True,
        'fips_profile': FIPS_PROFILE,
        'region': os.environ.get('VPNAAS_REGION', 'unspecified'),
        'tenant_id': os.environ.get('VPNAAS_TENANT_ID', ''),
        'instance_id': os.environ.get('VPNAAS_INSTANCE_ID', ''),
        'public_ip': public_ip(),
        'bind_ip': bind_ip(),
        'public_if': public_if(),
        'lan_cidr': effective_lan,
        'vpc_cidrs': detected_vpcs,
        'pool_cidr': str(network()),
        'route_auto': os.environ.get('VPNAAS_ROUTE_AUTO') == '1',
        'counts': counts,
        'capabilities': {
            'fips_ikev2_only': True,
            'split_tunnel_default': True,
            'golden_image_bootstrap': True,
            'ikev2_s2s_multisite': True,
            'ikev2_s2s_hub_legacy': True,
            'ikev2_s2s_direct_legacy': True,
            'ikev2_c2s_eap_mschapv2': True,
            'ikev2_c2s_cert_pubkey': True,
            'ikev2_c2s_eap_tls': True,
            'c2s_allow_vpc': True,
            'c2s_allow_all_sites': True,
            'c2s_groups': True,
            'c2s_to_s2s': True,
            'site_last_connected': True,
            's2s_zero_touch_narrowing': True,
            'static_routing': True,
            'granular_acl_ports_deny': True,
            'pki_crl': True,
            'vendor_configs': ['generic', 'swanctl', 'script', 'mikrotik', 'fortigate', 'cisco'],
            'client_profiles': ['json', 'mobileconfig', 'sswan', 'windows', 'manual'],
            'token_rbac': True,
            'openvpn': False,
            'bgp': False,
        },
        'pki': {'ca': pki.ca_info(), 'server': pki.server_info()},
        'future_presets': tuning.PRESETS,
    }


@app.get('/api/audit', dependencies=[Depends(require_readonly)])
def audit_list(
    resource: Optional[str] = Query(default=None),
    action: Optional[str] = Query(default=None),
    limit: int = Query(default=500, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
):
    clauses = []
    params = []
    if resource:
        clauses.append('resource = ?')
        params.append(resource)
    if action:
        clauses.append('action = ?')
        params.append(action)
    where = (' WHERE ' + ' AND '.join(clauses)) if clauses else ''
    sql = f'SELECT id, timestamp, action, resource, resource_id FROM audit{where} ORDER BY id DESC LIMIT ? OFFSET ?'
    params.extend([limit, offset])
    with lock:
        return [
            dict(zip(['id', 'timestamp', 'action', 'resource', 'resource_id'], r))
            for r in db.execute(sql, params)
        ]


@app.get('/api/status', dependencies=[Depends(require_readonly)])
def vpn_status():
    if os.environ.get('VPNAAS_DRY_RUN') == '1':
        return {'raw': 'test mode (not daemon status)', 'connections': ''}
    from vpn import status
    try:
        result = status()
        if os.environ.get('VPNAAS_ROUTE_AUTO') == '1':
            from network import diagnostics
            with lock:
                u_rows = rows('users')
                c_rows = rows('connections')
                s_rows = rows('sites')
                g_rows = rows('groups')
                r_rows = rows('routes')
            result['network'] = diagnostics(u_rows, connections=c_rows, sites=s_rows, groups=g_rows, routes=r_rows)
        return result
    except Exception:
        raise HTTPException(503, 'strongSwan status unavailable')


@app.get('/api/overview', dependencies=[Depends(require_readonly)])
def overview():
    with lock:
        result = {k: len(rows(k)) for k in ['connections', 'users', 'policies', 'sites', 'groups', 'routes', 'certs']}
        result['enabled_connections'] = sum(r['enabled'] for r in rows('connections'))
        result['enabled_sites'] = sum(r.get('enabled', True) for r in rows('sites'))
    result['vpn'] = vpn_status()
    return result


# ---------- Token-Based Auth Management (Admin Only) ----------

@app.get('/api/tokens', dependencies=[Depends(require_admin)])
def api_tokens_list():
    return list_tokens()


@app.post('/api/tokens', dependencies=[Depends(require_admin)])
def api_tokens_create(body: dict):
    created = create_token(body)
    return JSONResponse(created, headers={'Cache-Control': 'no-store'})


@app.delete('/api/tokens/{ident}', dependencies=[Depends(require_admin)])
def api_tokens_revoke(ident: int):
    return revoke_token(ident)


# ---------- C2S User Profiles & Explicit Session Disconnect ----------

@app.get('/api/users/{ident}/profile', dependencies=[Depends(require_operator)])
def profile(
    ident: int,
    format: Literal['json', 'mobileconfig', 'sswan', 'windows', 'manual'] = 'json',
    p12_passphrase: str = Query(default=''),
):
    import pki
    import profiles

    with lock:
        u = get('users', ident)
        g_rows = rows('groups')
        s_rows = rows('sites')
        r_rows = rows('routes')
        cert_row = get('certs', u['cert_id']) if u.get('cert_id') else None

    eff_cidrs = effective_user_cidrs(u, g_rows, s_rows, r_rows)
    if u.get('traffic_mode', 'split') != 'full' and not eff_cidrs:
        raise HTTPException(409, 'Akun tidak memiliki jaringan aktif (site/grup terkait sedang nonaktif)')
    ca_pem = pki.ca_pem()
    data = profiles.build_json_profile(u, ca_pem, eff_cidrs, cert_row=cert_row)

    if format == 'json':
        # Preserve exact backward-compatible filename for existing UI/scripts.
        return JSONResponse(
            data,
            headers={
                'Cache-Control': 'no-store',
                'Content-Disposition': f'attachment; filename="user-{ident}.json"',
            },
        )

    p12_bytes = None
    if cert_row and cert_row.get('cert_pem') and cert_row.get('private_key_pem'):
        p12_bytes = pki.build_pkcs12(
            cert_row['cert_pem'],
            cert_row['private_key_pem'],
            ca_pem,
            friendly_name=u['username'],
            passphrase=p12_passphrase,
        )

    if format == 'mobileconfig':
        xml, fname = profiles.build_mobileconfig(data, p12_bytes=p12_bytes)
        return Response(
            content=xml,
            media_type='application/x-apple-aspen-config',
            headers={'Cache-Control': 'no-store', 'Content-Disposition': f'attachment; filename="{fname}"'},
        )
    if format == 'sswan':
        text, fname = profiles.build_sswan(data, p12_bytes=p12_bytes)
        return Response(
            content=text,
            media_type='application/vnd.strongswan.profile+json',
            headers={'Cache-Control': 'no-store', 'Content-Disposition': f'attachment; filename="{fname}"'},
        )
    if format == 'manual':
        txt, fname = profiles.build_manual_conf(data)
        return PlainTextResponse(
            txt,
            headers={'Cache-Control': 'no-store', 'Content-Disposition': f'attachment; filename="{fname}"'},
        )
    ps1, fname = profiles.build_windows_ps1(data)
    return PlainTextResponse(
        ps1,
        headers={'Cache-Control': 'no-store', 'Content-Disposition': f'attachment; filename="{fname}"'},
    )


@app.post('/api/users/{ident}/disconnect', dependencies=[Depends(require_operator)])
def user_disconnect_all(ident: int):
    from vpn import disconnect_user
    with lock:
        u = get('users', ident)
    res = disconnect_user(u)
    with lock:
        audit('disconnect', 'users', ident)
        db.commit()
    return res


@app.post('/api/users/{ident}/sessions/{ike_id}/disconnect', dependencies=[Depends(require_operator)])
def user_disconnect_session(ident: int, ike_id: str):
    from vpn import disconnect_user
    with lock:
        u = get('users', ident)
    res = disconnect_user(u, ike_id=ike_id)
    with lock:
        audit('disconnect_session', 'users', ident)
        db.commit()
    return res


# ---------- Multi-Site S2S Actions & Multi-Vendor Config ----------

@app.get('/api/sites/{ident}/config', dependencies=[Depends(require_operator)])
def site_n_config(
    ident: int,
    vendor: Literal['generic', 'swanctl', 'script', 'mikrotik', 'fortigate', 'cisco'] = 'swanctl',
    dynamic_ts: bool = Query(default=True),
):
    from vpn import site_local_ts
    import vendors

    with lock:
        s = get('sites', ident)
        all_sites = rows('sites')
        all_users = rows('users')
        all_groups = rows('groups')
        all_policies = rows('policies')
        all_routes = rows('routes')
        cert_row = get('certs', s['cert_id']) if s.get('cert_id') else None
    local_ts = site_local_ts(s, sites=all_sites, users=all_users, groups=all_groups, policies=all_policies, routes=all_routes)
    text, fname = vendors.generate_for_site(s, local_ts, vendor=vendor, routes=all_routes, dynamic_ts=dynamic_ts, cert_row=cert_row)
    return PlainTextResponse(
        text,
        headers={'Cache-Control': 'no-store', 'Content-Disposition': f'attachment; filename="{fname}"'},
    )


@app.post('/api/sites/{ident}/connect', dependencies=[Depends(require_operator)])
def site_n_connect(ident: int):
    from vpn import site_n_action
    with lock:
        s = get('sites', ident)
    return site_n_action(s, 'connect')


@app.post('/api/sites/{ident}/disconnect', dependencies=[Depends(require_operator)])
def site_n_disconnect(ident: int):
    from vpn import site_n_action
    with lock:
        s = get('sites', ident)
    return site_n_action(s, 'disconnect')


# ---------- Legacy Hub & Direct S2S Actions & Multi-Vendor Config ----------

@app.post('/api/connections/{ident}/initiate', dependencies=[Depends(require_operator)])
def initiate(ident: int):
    from vpn import action
    with lock:
        return action(get('connections', ident), 'initiate')


@app.post('/api/connections/{ident}/terminate', dependencies=[Depends(require_operator)])
def terminate(ident: int):
    from vpn import action
    with lock:
        return action(get('connections', ident), 'terminate')


@app.get('/api/connections/{ident}/sites/{side}/config', dependencies=[Depends(require_operator)])
def site_config(
    ident: int,
    side: Literal['a', 'b'],
    format: Literal['swanctl', 'script', 'mikrotik', 'fortigate', 'cisco'] = 'swanctl',
):
    from vpn import is_hub
    import vendors

    with lock:
        c = get('connections', ident)
    if not is_hub(c):
        raise HTTPException(409, 'Bukan koneksi VPN Hub')
    text, filename = vendors.generate_for_hub(c, side, vendor=format)
    return PlainTextResponse(
        text,
        headers={'Cache-Control': 'no-store', 'Content-Disposition': f'attachment; filename="{filename}"'},
    )


@app.post('/api/connections/{ident}/sites/{side}/connect', dependencies=[Depends(require_operator)])
def site_connect(ident: int, side: Literal['a', 'b']):
    from vpn import site_action
    with lock:
        c = get('connections', ident)
    return site_action(c, side, 'connect')


@app.post('/api/connections/{ident}/sites/{side}/disconnect', dependencies=[Depends(require_operator)])
def site_disconnect(ident: int, side: Literal['a', 'b']):
    from vpn import site_action
    with lock:
        c = get('connections', ident)
    return site_action(c, side, 'disconnect')


# ---------- PKI & Certificate Authority Endpoints ----------

@app.get('/api/pki/ca', dependencies=[Depends(require_readonly)])
def pki_ca_status():
    import pki
    return pki.ca_info()


@app.get('/api/pki/ca/cert', dependencies=[Depends(require_readonly)])
def pki_ca_download(format: Literal['pem', 'crt'] = 'pem'):
    import pki
    pem = pki.ca_pem()
    if not pem:
        raise HTTPException(404, 'CA certificate not found')
    if format == 'crt':
        return PlainTextResponse(
            pem,
            media_type='application/x-x509-ca-cert',
            headers={'Content-Disposition': 'attachment; filename="vpnaas-ca.crt"'},
        )
    return PlainTextResponse(
        pem,
        media_type='application/x-pem-file',
        headers={'Content-Disposition': 'attachment; filename="vpnaas-ca.pem"'},
    )


@app.get('/api/pki/server', dependencies=[Depends(require_readonly)])
def pki_server_status():
    import pki
    return pki.server_info()


@app.post('/api/pki/server/rotate', dependencies=[Depends(require_admin)])
def pki_server_rotate(body: Optional[dict] = Body(default=None)):
    import pki
    body = body or {}
    if not isinstance(body, dict) or set(body) - {'public_ip', 'extra_sans', 'validity_days'}:
        raise HTTPException(422, 'Unknown fields')
    result = pki.rotate_server_cert(
        public_ip=body.get('public_ip'),
        extra_sans=body.get('extra_sans'),
        validity_days=body.get('validity_days', 825),
    )
    with lock:
        audit('rotate', 'pki_server', 0)
        db.commit()
    return result


def _refresh_cert_expiry(row: dict) -> dict:
    """Recompute days_remaining and expired dynamically from not_after so persisted cert rows never go stale."""
    import datetime
    out = dict(row)
    not_after_s = out.get('not_after')
    if out.get('no_expiration') or (isinstance(not_after_s, str) and not_after_s.startswith('9999-')):
        out['no_expiration'] = True
        out['days_remaining'] = None
        out['expired'] = False
        return out
    if isinstance(not_after_s, str) and not_after_s:
        try:
            na = datetime.datetime.fromisoformat(not_after_s.replace('Z', '+00:00'))
            if na.tzinfo is None:
                na = na.replace(tzinfo=datetime.timezone.utc)
            now = datetime.datetime.now(datetime.timezone.utc)
            out['no_expiration'] = False
            out['days_remaining'] = int((na - now).total_seconds() // 86400)
            out['expired'] = now >= na
        except ValueError:
            pass
    return out


@app.get('/api/pki/certs', dependencies=[Depends(require_readonly)])
def pki_certs_list():
    with lock:
        return [_refresh_cert_expiry(public(c)) for c in rows('certs')]


@app.get('/api/pki/certs/{ident}', dependencies=[Depends(require_readonly)])
def pki_certs_detail(ident: int):
    with lock:
        return _refresh_cert_expiry(public(get('certs', ident)))


@app.post('/api/pki/certs', dependencies=[Depends(require_operator)])
def pki_certs_issue(body: dict):
    import pki
    from store import safe

    if not isinstance(body, dict) or set(body) - {'name', 'san', 'target_type', 'validity_days', 'no_expiration'}:
        raise HTTPException(422, 'Unknown fields')
    try:
        name = safe(body.get('name'))
    except ValueError:
        raise HTTPException(422, 'name wajib (A-Z a-z 0-9 _ @ . : -)')
    target_type = body.get('target_type', 'user')
    if target_type not in ('user', 'site'):
        raise HTTPException(422, 'target_type harus user atau site')
    san = body.get('san') or f'{name}@vpnaas'
    try:
        san = safe(san)
    except ValueError:
        raise HTTPException(422, 'san tidak valid')
    no_exp = body.get('no_expiration', False)
    if type(no_exp) is not bool:
        raise HTTPException(422, 'no_expiration harus boolean')
    validity_days = None if no_exp else body.get('validity_days', 365)

    cert_pem, key_pem, meta = pki.issue_leaf_cert(
        name, san, target_type=target_type, validity_days=validity_days, no_expiration=no_exp
    )
    record = {
        'name': name,
        'san': san,
        'target_type': target_type,
        'revoked': False,
        'revoked_at': None,
        'cert_pem': cert_pem,
        'private_key_pem': key_pem,
        **meta,
    }
    with lock:
        cur = db.execute('INSERT INTO objects(kind,body) VALUES(?,?)', ('certs', json.dumps(record)))
        ident = cur.lastrowid
        audit('issue', 'certs', ident)
        db.commit()
    return public(dict(record, id=ident))


@app.get('/api/pki/certs/{ident}/bundle', dependencies=[Depends(require_operator)])
def pki_certs_bundle(
    ident: int,
    format: Literal['pem', 'p12', 'crt', 'key'] = 'pem',
    passphrase: str = Query(default=''),
):
    import pki
    import profiles

    with lock:
        cert = get('certs', ident)
    ca_pem = pki.ca_pem()
    safe_name = profiles._safe_filename(cert['name'])
    if format == 'crt':
        return PlainTextResponse(
            cert['cert_pem'],
            media_type='application/x-x509-ca-cert',
            headers={'Cache-Control': 'no-store', 'Content-Disposition': f'attachment; filename="{safe_name}.crt"'},
        )
    if format == 'key':
        return PlainTextResponse(
            cert['private_key_pem'],
            media_type='application/x-pem-file',
            headers={'Cache-Control': 'no-store', 'Content-Disposition': f'attachment; filename="{safe_name}.key"'},
        )
    if format == 'p12':
        raw = pki.build_pkcs12(
            cert['cert_pem'],
            cert['private_key_pem'],
            ca_pem,
            friendly_name=cert['name'],
            passphrase=passphrase,
        )
        return Response(
            content=raw,
            media_type='application/x-pkcs12',
            headers={'Cache-Control': 'no-store', 'Content-Disposition': f'attachment; filename="{safe_name}.p12"'},
        )
    return JSONResponse(
        {
            'id': cert['id'],
            'name': cert['name'],
            'san': cert['san'],
            'target_type': cert['target_type'],
            'serial': cert['serial'],
            'cert_pem': cert['cert_pem'],
            'private_key_pem': cert['private_key_pem'],
            'ca_pem': ca_pem,
        },
        headers={'Cache-Control': 'no-store', 'Content-Disposition': f'attachment; filename="{safe_name}-bundle.json"'},
    )


@app.post('/api/pki/certs/{ident}/revoke', dependencies=[Depends(require_operator)])
def pki_certs_revoke(ident: int):
    import datetime
    import pki
    from vpn import revoke as revoke_sa

    with lock:
        cert = get('certs', ident)
        try:
            if not cert.get('revoked'):
                cert['revoked'] = True
                cert['revoked_at'] = datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
                body = {k: v for k, v in cert.items() if k != 'id'}
                db.execute('UPDATE objects SET body=? WHERE id=?', (json.dumps(body), ident))
            revoked_rows = [c for c in rows('certs') if c.get('revoked')]
            affected_users = [u for u in rows('users') if u.get('cert_id') == ident]
            affected_sites = [s for s in rows('sites') if s.get('cert_id') == ident]
            pki.rebuild_crl(revoked_rows)
            for u in affected_users:
                revoke_sa('users', u['id'])
            for s in affected_sites:
                revoke_sa('sites', s['id'])
            audit('revoke', 'certs', ident)
            db.commit()
        except Exception:
            db.rollback()
            raise
    return {'revoked': True, 'id': ident, 'serial': cert.get('serial'), 'crl_entries': len(revoked_rows)}


@app.get('/api/pki/crl', dependencies=[Depends(require_readonly)])
def pki_crl_download():
    import pki
    pem = pki.read_crl_pem()
    if not pem:
        raise HTTPException(404, 'CRL not generated yet')
    return PlainTextResponse(
        pem,
        media_type='application/pkix-crl',
        headers={'Content-Disposition': 'attachment; filename="vpnaas-ca.crl"'},
    )


# ---------- Monitoring, Logs & Connectivity Diagnostics ----------

@app.get('/api/monitoring/tunnels', dependencies=[Depends(require_readonly)])
def monitoring_tunnels():
    from runtime import tunnels_summary
    with lock:
        u_rows = [public(u) for u in rows('users')]
        s_rows = [public(s) for s in rows('sites')]
        c_rows = [public(c) for c in rows('connections')]
    return tunnels_summary(u_rows, s_rows, c_rows)


def _redact_log(text: str) -> str:
    return _LOG_REDACT.sub(lambda m: f'{m.group(1)}=[REDACTED]' if m.group(2) else '[REDACTED]', text)


@app.get('/api/logs', dependencies=[Depends(require_readonly)])
def service_logs(
    source: Literal['strongswan', 'api', 'reconcile', 'offload'] = 'strongswan',
    lines: int = Query(default=100, ge=1, le=500),
):
    unit_map = {
        'strongswan': 'strongswan.service',
        'api': 'vpnaas-api.service',
        'reconcile': 'vpnaas-reconcile.service',
        'offload': 'vpnaas-offload.service',
    }
    unit = unit_map[source]
    if os.environ.get('VPNAAS_DRY_RUN') == '1':
        return {'source': source, 'unit': unit, 'lines': [], 'note': 'dry-run mode'}
    try:
        proc = subprocess.run(
            ['journalctl', '-u', unit, '-n', str(lines), '--no-pager', '-o', 'short-iso'],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if proc.returncode != 0:
            raise RuntimeError(proc.stderr.strip() or 'journalctl failed')
        cleaned = [_redact_log(line) for line in proc.stdout.splitlines()]
        return {'source': source, 'unit': unit, 'lines': cleaned}
    except Exception:
        raise HTTPException(503, f'Unable to read logs for {unit}')


def _diag_proto_port_match(policy, proto, port):
    p_proto = policy.get('protocol', 'all')
    if p_proto != 'all' and p_proto != proto:
        return False
    p_ports = policy.get('ports')
    if not p_ports or p_proto not in ('tcp', 'udp'):
        return True
    if port is None:
        return True
    for part in str(p_ports).split(','):
        part = part.strip()
        if not part:
            continue
        if '-' in part:
            lo, hi = part.split('-', 1)
            if int(lo) <= port <= int(hi):
                return True
        elif int(part) == port:
            return True
    return False


def _diag_policy_dst_nets(policy, matched_site, target_net, all_routes):
    dt = policy.get('destination_type', 'cidr')
    if dt == 'cidr' and policy.get('destination_cidr'):
        return [ipaddress.IPv4Network(policy['destination_cidr'])]
    if dt == 'site' and matched_site and policy.get('destination_ref') == matched_site['id']:
        return [target_net]
    if dt == 'vpc':
        return [ipaddress.IPv4Network(vc) for vc in vpc_cidrs(all_routes)]
    return []


@app.post('/api/diagnostics/check', dependencies=[Depends(require_operator)])
def diagnostics_check(body: dict):
    """Verify tunnel + route + policy path readiness for a target IPv4 address/CIDR."""
    if not isinstance(body, dict) or set(body) - {'target', 'source_user_id', 'source_site_id', 'protocol', 'port', 'ping'}:
        raise HTTPException(422, 'Unknown fields')
    raw_target = body.get('target')
    if not isinstance(raw_target, str):
        raise HTTPException(422, 'target wajib berupa IPv4 atau CIDR')
    try:
        if '/' in raw_target:
            target_net = ipaddress.IPv4Network(raw_target, strict=False)
            target_ip = str(target_net.network_address)
        else:
            target_ip = str(ipaddress.IPv4Address(raw_target))
            target_net = ipaddress.IPv4Network(target_ip + '/32')
    except ValueError:
        raise HTTPException(422, 'target harus IPv4 atau CIDR IPv4 valid')

    proto = body.get('protocol', 'all')
    if proto not in ('all', 'tcp', 'udp', 'icmp'):
        raise HTTPException(422, 'protocol harus all, tcp, udp, atau icmp')
    port = body.get('port')
    if port is not None and (type(port) is not int or not 1 <= port <= 65535):
        raise HTTPException(422, 'port harus integer 1..65535')
    do_ping = bool(body.get('ping', False))

    with lock:
        all_users = rows('users')
        all_groups = rows('groups')
        all_sites = rows('sites')
        all_conns = rows('connections')
        all_policies = rows('policies')
        all_routes = rows('routes')
        src_user = get('users', body['source_user_id']) if body.get('source_user_id') is not None else None
        src_site = get('sites', body['source_site_id']) if body.get('source_site_id') is not None else None

    # 1. Identify whether target belongs to a configured S2S site/connection or Gateway LAN/static route
    matched_site = None
    for s in all_sites:
        if not s.get('enabled', True):
            continue
        if any(target_net.subnet_of(ipaddress.IPv4Network(c)) for c in site_effective_subnets(s, all_routes)):
            matched_site = s
            break

    matched_hub = None
    if not matched_site:
        for c in all_conns:
            if not c.get('enabled', True):
                continue
            if c.get('topology') == 'hub':
                for side in ('site_a', 'site_b'):
                    if any(target_net.subnet_of(ipaddress.IPv4Network(x)) for x in ts_split(c[side]['subnets'])):
                        matched_hub = (c, side)
                        break
            else:
                if any(target_net.subnet_of(ipaddress.IPv4Network(x)) for x in ts_split(c['remote_ts'])):
                    matched_hub = (c, 'direct')
                    break

    # 2. Evaluate effective ACL / policy decision
    ordered_policies = sorted(
        [p for p in all_policies if p.get('enabled', True)],
        key=lambda x: (x.get('priority', 100), x['id']),
    )
    policy_allowed = None
    policy_reason = 'no source specified'
    if src_user:
        eff = [ipaddress.IPv4Network(c) for c in effective_user_cidrs(src_user, all_groups, all_sites, all_routes)]
        in_grants = any(target_net.subnet_of(n) for n in eff)
        explicit_deny = False
        for p in ordered_policies:
            if p.get('action', 'allow') != 'deny':
                continue
            src_match = (p.get('source_type') == 'user' and p.get('source_ref') == src_user['id']) or (
                p.get('source_type') == 'group' and p.get('source_ref') in src_user.get('groups', [])
            )
            if not src_match:
                continue
            dst_nets = _diag_policy_dst_nets(p, matched_site, target_net, all_routes)
            if any(target_net.subnet_of(dn) for dn in dst_nets) and _diag_proto_port_match(p, proto, port):
                explicit_deny = True
                policy_reason = f"Blocked by deny policy '{p['name']}'"
                break
        if explicit_deny:
            policy_allowed = False
        elif in_grants:
            policy_allowed = True
            policy_reason = 'Permitted by user/group allowed_cidrs or allowed_sites'
        elif src_user.get('traffic_mode') == 'full' and not target_net.is_private:
            policy_allowed = True
            policy_reason = 'Permitted via full-tunnel public internet egress'
        else:
            policy_allowed = False
            policy_reason = 'Denied by default-deny policy'
    elif src_site:
        from vpn import _sites_are_peered
        src_site_nets = [ipaddress.IPv4Network(c) for c in site_effective_subnets(src_site, all_routes)]

        def _match_site_policy(action):
            for p in ordered_policies:
                if p.get('action', 'allow') != action:
                    continue
                st = p.get('source_type', 'cidr')
                src_match = (st == 'site' and p.get('source_ref') == src_site['id']) or (
                    st == 'cidr' and p.get('source_cidr') and any(sn.overlaps(ipaddress.IPv4Network(p['source_cidr'])) for sn in src_site_nets)
                )
                if not src_match:
                    continue
                dst_nets = _diag_policy_dst_nets(p, matched_site, target_net, all_routes)
                if any(target_net.subnet_of(dn) for dn in dst_nets) and _diag_proto_port_match(p, proto, port):
                    return p
            return None

        # Explicit DENY policies run BEFORE peer_sites / allow_vpc / allow policies (matching vpn.firewall).
        blocked_by = _match_site_policy('deny')
        if blocked_by:
            policy_allowed = False
            policy_reason = f"Blocked by deny policy '{blocked_by['name']}'"
        elif matched_site:
            if src_site['id'] == matched_site['id']:
                policy_allowed = True
                policy_reason = 'Same site'
            elif _sites_are_peered(src_site, matched_site):
                policy_allowed = True
                policy_reason = f"Permitted by bidirectional site peering ({src_site['name']} <-> {matched_site['name']})"
            else:
                # Directional ALLOW match (matching nftables chain forward: only source -> destination is permitted).
                allowed_p = _match_site_policy('allow')
                policy_allowed = bool(allowed_p)
                policy_reason = f"Permitted by policy '{allowed_p['name']}'" if allowed_p else 'Denied by default-deny inter-site policy'
        else:
            vpc_nets = [ipaddress.IPv4Network(vc) for vc in vpc_cidrs(all_routes)]
            if any(target_net.subnet_of(vn) for vn in vpc_nets) and src_site.get('allow_vpc', True):
                policy_allowed = True
                policy_reason = f"Permitted by site allow_vpc ({src_site['name']} <-> VPC)"
            else:
                allowed_p = _match_site_policy('allow')
                policy_allowed = bool(allowed_p)
                policy_reason = f"Permitted by policy '{allowed_p['name']}'" if allowed_p else 'Denied by default-deny policy'

    # 3. Kernel route & Tunnel status
    route_info = {'available': False, 'interface': None}
    tunnel_status = None
    if matched_site:
        from runtime import site_runtime
        st = site_runtime([matched_site])[matched_site['id']]
        tunnel_status = {'type': 'site', 'id': matched_site['id'], 'name': matched_site['name'], 'status': st['status']}
        route_info = {'available': st['status'] == 'active', 'interface': 'ipsec'}
    elif matched_hub:
        c, side = matched_hub
        if side == 'direct':
            from runtime import direct_runtime
            st = direct_runtime([c])[c['id']]
            tunnel_status = {'type': 'direct', 'id': c['id'], 'name': c['name'], 'status': st['runtime_status']}
            route_info = {'available': st['runtime_status'] == 'active', 'interface': 'ipsec'}
        else:
            from runtime import hub_runtime
            st = hub_runtime([c])[c['id']][side]
            tunnel_status = {'type': 'hub', 'id': c['id'], 'name': c['name'], 'side': side, 'status': st['status']}
            route_info = {'available': st['status'] == 'active', 'interface': 'ipsec'}
    elif os.environ.get('VPNAAS_DRY_RUN') != '1':
        try:
            from network import private_route, public_interface, snapshot
            kroutes = snapshot()
            pub = public_interface(kroutes)
            dev = private_route(str(target_net), kroutes, pub)
            route_info = {'available': bool(dev), 'interface': dev}
        except Exception:
            route_info = {'available': False, 'interface': None}

    ping_result = None
    if do_ping:
        if os.environ.get('VPNAAS_DRY_RUN') == '1':
            ping_result = {'skipped': True, 'reason': 'dry-run'}
        else:
            try:
                p = subprocess.run(['ping', '-4', '-c', '2', '-W', '2', target_ip], capture_output=True, text=True, timeout=8)
                ping_result = {'reachable': p.returncode == 0, 'output': p.stdout.strip()[-400:]}
            except Exception as exc:
                ping_result = {'reachable': False, 'error': str(exc)}

    return {
        'target': str(target_net),
        'route': route_info,
        'tunnel': tunnel_status,
        'policy': {'allowed': policy_allowed, 'reason': policy_reason},
        'ping': ping_result,
    }
