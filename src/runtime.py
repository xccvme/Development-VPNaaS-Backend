"""Read-only strongSwan raw VICI events; never infer liveness from config."""
import os
import re

_TOKEN = re.compile(r'\s*("(?:\\.|[^"\\])*"|[^\s{}\[\]=]+|[{}\[\]=])')


def parse_sas(raw):
    if len(raw) > 4_000_000:
        raise ValueError('Status too large')
    tokens = _TOKEN.findall(raw)
    pos = 0

    def take():
        nonlocal pos
        if pos >= len(tokens):
            raise ValueError('Truncated status')
        token = tokens[pos]
        pos += 1
        return token

    def section():
        result = {}
        while True:
            key = take()
            if key == '}':
                return result
            if key in '{}[]=':
                raise ValueError('Invalid key')
            delimiter = take()
            if delimiter == '{':
                value = section()
            elif delimiter == '=':
                value = take()
                if value == '[':
                    value = []
                    while (item := take()) != ']':
                        if item in '{}[=':
                            raise ValueError('Invalid list')
                        value.append(item.strip('"'))
                elif value in '{}]=':
                    raise ValueError('Invalid scalar')
                else:
                    value = value.strip('"')
            else:
                raise ValueError('Invalid delimiter')
            if key in result:
                raise ValueError('Duplicate key')
            result[key] = value

    sas = []
    complete = False
    while pos < len(tokens):
        name, kind, opening = take(), take(), take()
        if opening != '{':
            raise ValueError('Invalid status event')
        data = section()
        if name == 'list-sa' and kind == 'event':
            if not all(isinstance(sa, dict) for sa in data.values()):
                raise ValueError('Invalid SA')
            sas.extend(dict(sa, name=name) for name, sa in data.items())
        elif name == 'list-sas' and kind == 'reply' and data.get('success') != 'no':
            complete = True
        else:
            raise ValueError('Unexpected status event')
    if not complete:
        raise ValueError('Incomplete status')
    return sas


def _read_sas():
    if os.environ.get('VPNAAS_DRY_RUN') == '1':
        raise ValueError('No runtime in dry-run')
    from vici_client import list_sas
    return list_sas()


def _format_remote(sa):
    host = sa.get('remote-host')
    if not host:
        return None
    port = sa.get('remote-port')
    return f'{host}:{port}' if port else host


def _user_matches_sa(user, sa):
    # Authenticated EAP identity takes precedence over configuration name.
    identity = sa.get('remote-eap-id') or sa.get('remote-xauth-id')
    if identity:
        return identity == user['username']
    # Mutual certificate / pubkey auth: match exact conn name `user-<id>`
    return sa.get('name') == 'user-' + str(user['id'])


def user_runtime(users, sas=None):
    from store import get_telemetry_map, record_telemetry_batch
    telem = get_telemetry_map('users')

    def unknown(uid):
        t = telem.get(uid) or {}
        return {
            'runtime_status': 'Unknown',
            'online': None,
            'session_count': None,
            'virtual_ips': [],
            'sessions': [],
            'last_connected_at': t.get('last_connected_at'),
            'last_remote_host': t.get('last_remote_host'),
        }

    try:
        if sas is None:
            sas = _read_sas()
        result = {}
        active_updates = []
        for user in users:
            sessions = []
            for sa in sas:
                if not _user_matches_sa(user, sa):
                    continue
                children = []
                for child in (sa.get('child-sas') or {}).values():
                    if isinstance(child, dict) and child.get('state') == 'INSTALLED':
                        children.append({
                            'child_id': child.get('uniqueid'),
                            'state': 'INSTALLED',
                            'bytes_in': int(child.get('bytes-in', 0)),
                            'bytes_out': int(child.get('bytes-out', 0)),
                        })
                sessions.append({
                    'ike_id': sa.get('uniqueid'),
                    'ike_state': sa.get('state'),
                    'remote_address': sa.get('remote-host'),
                    'remote_port': sa.get('remote-port'),
                    'established_sec': int(sa.get('established', 0)) if str(sa.get('established', '')).isdigit() else None,
                    'virtual_ips': sa.get('remote-vips', []),
                    'children': children,
                })
            active_sessions = [s for s in sessions if s['ike_state'] == 'ESTABLISHED' and s['children']]
            active = bool(active_sessions)
            first_remote = None
            if active_sessions:
                raddr = active_sessions[0].get('remote_address')
                rport = active_sessions[0].get('remote_port')
                first_remote = f'{raddr}:{rport}' if (raddr and rport) else raddr
                active_updates.append((user['id'], first_remote))
            result[user['id']] = {
                'runtime_status': 'Active' if active else 'Down',
                'online': active,
                'session_count': len(active_sessions),
                'virtual_ips': sorted({ip for s in sessions for ip in s['virtual_ips']}),
                'sessions': sessions,
                'last_remote_host': first_remote,
            }
        if active_updates:
            try:
                telem = record_telemetry_batch('users', active_updates)
            except Exception:
                pass
        for uid, entry in result.items():
            t = telem.get(uid) or {}
            entry['last_connected_at'] = t.get('last_connected_at')
            if not entry['last_remote_host']:
                entry['last_remote_host'] = t.get('last_remote_host')
        return result
    except Exception:
        # Never label missing/invalid daemon telemetry as disconnected.
        return {user['id']: unknown(user['id']) for user in users}


def _sa_state_for_conn(sas, conn_name):
    state = {
        'status': 'down',
        'remote_host': None,
        'bytes_in': 0,
        'bytes_out': 0,
        'ike_sa_id': None,
        'established_sec': None,
    }
    for sa in sas:
        if sa.get('name') != conn_name:
            continue
        children = [
            ch for ch in (sa.get('child-sas') or {}).values()
            if isinstance(ch, dict) and ch.get('state') == 'INSTALLED'
        ]
        active = sa.get('state') == 'ESTABLISHED' and bool(children)
        if state['status'] == 'active' and not active:
            continue
        remote = _format_remote(sa)
        if remote:
            state['remote_host'] = remote
        if sa.get('uniqueid'):
            state['ike_sa_id'] = sa.get('uniqueid')
        if str(sa.get('established', '')).isdigit():
            state['established_sec'] = int(sa['established'])
        if active:
            state['status'] = 'active'
            state['bytes_in'] += sum(int(ch.get('bytes-in', 0)) for ch in children)
            state['bytes_out'] += sum(int(ch.get('bytes-out', 0)) for ch in children)
    return state


def hub_runtime(connections, sas=None):
    """Per hub site: 'active' for ESTABLISHED+INSTALLED, 'down' on valid snapshot, 'unknown' on telemetry failure."""
    def unknown():
        return {'status': 'unknown', 'remote_host': None, 'bytes_in': 0, 'bytes_out': 0}

    try:
        if sas is None:
            sas = _read_sas()
    except Exception:
        return {c['id']: {'site_a': unknown(), 'site_b': unknown()} for c in connections}

    result = {}
    for c in connections:
        entry = {}
        for side in ('a', 'b'):
            st = _sa_state_for_conn(sas, f"hub-{c['id']}-{side}")
            entry['site_' + side] = {
                'status': st['status'],
                'remote_host': st['remote_host'],
                'bytes_in': st['bytes_in'],
                'bytes_out': st['bytes_out'],
            }
        result[c['id']] = entry
    return result


def direct_runtime(connections, sas=None):
    """Runtime telemetry for legacy direct S2S connections (`site-<id>`)."""
    def unknown():
        return {'runtime_status': 'unknown', 'remote_host': None, 'bytes_in': 0, 'bytes_out': 0}

    try:
        if sas is None:
            sas = _read_sas()
    except Exception:
        return {c['id']: unknown() for c in connections}

    result = {}
    for c in connections:
        st = _sa_state_for_conn(sas, f"site-{c['id']}")
        result[c['id']] = {
            'runtime_status': st['status'],
            'remote_host': st['remote_host'],
            'bytes_in': st['bytes_in'],
            'bytes_out': st['bytes_out'],
        }
    return result


def site_runtime(sites, sas=None):
    """Runtime telemetry for Multi-Site S2S peers (`site-n-<id>`), including online state & persisted last_connected_at."""
    from store import get_telemetry_map, record_telemetry_batch
    telem = get_telemetry_map('sites')

    def unknown(sid):
        t = telem.get(sid) or {}
        return {
            'status': 'unknown',
            'online': None,
            'connection_state': 'unknown',
            'remote_host': None,
            'last_remote_host': t.get('last_remote_host'),
            'last_connected_at': t.get('last_connected_at'),
            'bytes_in': 0,
            'bytes_out': 0,
            'ike_sa_id': None,
            'established_sec': None,
        }

    try:
        if sas is None:
            sas = _read_sas()
    except Exception:
        return {s['id']: unknown(s['id']) for s in sites}

    states = {}
    active_updates = []
    for s in sites:
        st = _sa_state_for_conn(sas, f"site-n-{s['id']}")
        is_online = st['status'] == 'active'
        st['online'] = is_online
        st['connection_state'] = 'online' if is_online else 'offline'
        if is_online:
            active_updates.append((s['id'], st['remote_host']))
        states[s['id']] = st

    if active_updates:
        try:
            telem = record_telemetry_batch('sites', active_updates)
        except Exception:
            pass

    for sid, st in states.items():
        t = telem.get(sid) or {}
        st['last_connected_at'] = t.get('last_connected_at')
        st['last_remote_host'] = st['remote_host'] or t.get('last_remote_host')
    return states


def tunnels_summary(users, sites, connections):
    """Unified monitoring snapshot across C2S, Multi-Site S2S, Hub S2S, and Direct S2S."""
    telemetry_available = True
    try:
        sas = _read_sas()
    except Exception:
        sas = None
        telemetry_available = False

    u_rt = user_runtime(users, sas=sas)
    s_rt = site_runtime(sites, sas=sas)
    hubs = [c for c in connections if c.get('topology') == 'hub']
    directs = [c for c in connections if c.get('topology', 'direct') != 'hub']
    h_rt = hub_runtime(hubs, sas=sas)
    d_rt = direct_runtime(directs, sas=sas)

    c2s_list = []
    total_in = 0
    total_out = 0
    active_c2s_sessions = 0
    c2s_users_online = 0
    for u in users:
        rt = u_rt[u['id']]
        u_in = sum(ch['bytes_in'] for s in rt['sessions'] for ch in s['children'])
        u_out = sum(ch['bytes_out'] for s in rt['sessions'] for ch in s['children'])
        total_in += u_in
        total_out += u_out
        if rt['session_count']:
            active_c2s_sessions += rt['session_count']
        if rt.get('online'):
            c2s_users_online += 1
        c2s_list.append({
            'id': u['id'],
            'username': u['username'],
            'enabled': u.get('enabled', True),
            'auth_method': u.get('auth_method', 'eap-mschapv2'),
            'runtime_status': rt['runtime_status'],
            'online': rt.get('online'),
            'last_connected_at': rt.get('last_connected_at'),
            'last_remote_host': rt.get('last_remote_host'),
            'session_count': rt['session_count'],
            'max_sessions': u.get('max_sessions', 3),
            'virtual_ips': rt['virtual_ips'],
            'bytes_in': u_in,
            'bytes_out': u_out,
        })

    site_list = []
    active_sites = 0
    for s in sites:
        rt = s_rt[s['id']]
        if rt['status'] == 'active':
            active_sites += 1
        total_in += rt['bytes_in']
        total_out += rt['bytes_out']
        site_list.append({
            'id': s['id'],
            'name': s['name'],
            'enabled': s.get('enabled', True),
            'auth_method': s.get('auth_method', 'psk'),
            'subnets': s.get('subnets', ''),
            **rt,
        })

    hub_list = []
    active_hub_legs = 0
    for c in hubs:
        rt = h_rt[c['id']]
        for side in ('site_a', 'site_b'):
            if rt[side]['status'] == 'active':
                active_hub_legs += 1
            total_in += rt[side]['bytes_in']
            total_out += rt[side]['bytes_out']
        hub_list.append({
            'id': c['id'],
            'name': c['name'],
            'enabled': c.get('enabled', True),
            'site_a': rt['site_a'],
            'site_b': rt['site_b'],
        })

    direct_list = []
    active_directs = 0
    for c in directs:
        rt = d_rt[c['id']]
        if rt['runtime_status'] == 'active':
            active_directs += 1
        total_in += rt['bytes_in']
        total_out += rt['bytes_out']
        direct_list.append({
            'id': c['id'],
            'name': c['name'],
            'enabled': c.get('enabled', True),
            'remote_address': c.get('remote_address'),
            **rt,
        })

    return {
        'telemetry_available': telemetry_available,
        'totals': {
            'c2s_active_sessions': active_c2s_sessions,
            'c2s_users_online': c2s_users_online,
            'sites_active': active_sites,
            'sites_offline': max(0, len(sites) - active_sites) if telemetry_available else 0,
            'sites_total': len(sites),
            'hub_legs_active': active_hub_legs,
            'hub_legs_total': len(hubs) * 2,
            'direct_active': active_directs,
            'direct_total': len(directs),
            'bytes_in': total_in,
            'bytes_out': total_out,
        },
        'c2s': c2s_list,
        'sites': site_list,
        'hub_connections': hub_list,
        'direct_connections': direct_list,
    }
