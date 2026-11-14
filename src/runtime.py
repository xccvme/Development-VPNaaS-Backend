"""Read-only strongSwan raw VICI events; never infer liveness from config."""
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


def user_runtime(users):
    from vpn import run
    import os
    unknown = {'runtime_status': 'Unknown', 'session_count': None, 'virtual_ips': [], 'sessions': []}
    try:
        if os.environ.get('VPNAAS_DRY_RUN') == '1':
            raise ValueError('No runtime in dry-run')
        sas = parse_sas(run(['swanctl', '--list-sas', '--raw'], timeout=8))
        result = {}
        for user in users:
            sessions = []
            for sa in sas:
                # Authenticated EAP identity takes precedence over configuration name.
                identity = sa.get('remote-eap-id') or sa.get('remote-xauth-id')
                if (identity != user['username']) if identity else (sa['name'] != 'user-' + str(user['id'])):
                    continue
                children = []
                for child in sa.get('child-sas', {}).values():
                    if child.get('state') == 'INSTALLED':
                        children.append({'child_id': child.get('uniqueid'), 'state': 'INSTALLED',
                                         'bytes_in': int(child.get('bytes-in', 0)),
                                         'bytes_out': int(child.get('bytes-out', 0))})
                sessions.append({'ike_id': sa.get('uniqueid'), 'ike_state': sa.get('state'),
                                 'remote_address': sa.get('remote-host'),
                                 'virtual_ips': sa.get('remote-vips', []), 'children': children})
            active = any(s['ike_state'] == 'ESTABLISHED' and s['children'] for s in sessions)
            result[user['id']] = {'runtime_status': 'Active' if active else 'Down',
                                  'session_count': sum(s['ike_state'] == 'ESTABLISHED' and bool(s['children']) for s in sessions),
                                  'virtual_ips': sorted({ip for s in sessions for ip in s['virtual_ips']}),
                                  'sessions': sessions}
        return result
    except Exception:
        # Never label missing/invalid daemon telemetry as disconnected.
        return {user['id']: dict(unknown) for user in users}
