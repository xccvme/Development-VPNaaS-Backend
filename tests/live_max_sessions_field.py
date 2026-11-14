#!/usr/bin/env python3
"""Live max_sessions field check; prints status/keys only, never credentials."""
import json, secrets, subprocess, urllib.request, urllib.error
from pathlib import Path
key = Path('/etc/vpnaas/api.key').read_text().strip()


def api(path, body=None, method='GET'):
    req = urllib.request.Request('http://127.0.0.1:8000/api/' + path,
                                 data=json.dumps(body).encode() if body is not None else None,
                                 headers={'X-API-Key': key, 'Content-Type': 'application/json'}, method=method)
    try:
        r = urllib.request.urlopen(req, timeout=45)
        return r.status, json.load(r)
    except urllib.error.HTTPError as e:
        return e.code, json.load(e)


def sas():
    out = subprocess.run(['swanctl', '--list-sas', '--raw'], capture_output=True, text=True).stdout
    import re
    return re.findall(r'(site-30|user-21) \{uniqueid=(\d+)', out)


before = sas()
s, users = api('users')
u21 = next(u for u in users if u['id'] == 21)
print('GET users', s, 'user21', {k: u21.get(k) for k in ('username', 'max_sessions', 'session_count', 'runtime_status', 'enabled')})
s, d = api('users/21'); print('GET users/21', s, 'max_sessions', d.get('max_sessions'), 'session_count', d.get('session_count'))
s, u = api('users', {'username': 'tmp-maxsess-field', 'password': secrets.token_hex(12), 'enabled': True,
                     'allowed_cidrs': ['192.0.2.0/24'], 'traffic_mode': 'split', 'max_sessions': 1}, 'POST')
print('POST temp max_sessions=1', s, u.get('max_sessions'))
try:
    s, r = api(f"users/{u['id']}", {'username': 'tmp-maxsess-field', 'password': '', 'enabled': True,
                                    'allowed_cidrs': ['192.0.2.0/24'], 'traffic_mode': 'split', 'max_sessions': 3}, 'PUT')
    print('PUT temp max_sessions=3', s, r.get('max_sessions'))
    for bad in (0, -1, 4):
        print(f'PUT temp max_sessions={bad}', api(f"users/{u['id']}", {'max_sessions': bad}, 'PUT')[0])
    s, d = api(f"users/{u['id']}"); print('GET temp detail', s, d.get('max_sessions'), d.get('session_count'), d.get('runtime_status'))
finally:
    print('DELETE temp', api(f"users/{u['id']}", method='DELETE')[0])
after = sas()
print('SA ids site-30/user-21 before', before, 'after', after, 'unchanged', before == after)
s, users = api('users')
print('user21 after', next({k: x.get(k) for k in ('username', 'max_sessions', 'enabled')} for x in users if x['id'] == 21))
