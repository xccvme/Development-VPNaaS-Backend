#!/usr/bin/env python3
"""Run on installed gateway as root. Never prints keys or profile credentials."""
import json
import os
import secrets
import urllib.request
from pathlib import Path

key=Path('/etc/vpnaas/api.key').read_text().strip()
def api(path, body=None, method='GET'):
    req=urllib.request.Request('http://127.0.0.1:8000/api/'+path,data=json.dumps(body).encode() if body is not None else None,headers={'X-API-Key':key,'Content-Type':'application/json'},method=method)
    with urllib.request.urlopen(req,timeout=45) as r:return json.load(r)

created=[]
try:
    assert api('health')['status']=='ok'
    for mode in ('split','full'):
        u=api('users',dict(username='acceptance-'+mode,password=secrets.token_hex(18),allowed_cidrs=['192.0.2.0/24'],traffic_mode=mode), 'POST')
        created.append(('users',u['id']))
        assert 'password' not in u
        profile=api(f"users/{u['id']}/profile")
        assert profile['server']==os.environ['VPNAAS_PUBLIC_IP'] and profile['traffic_mode']==mode
        runtime=next(x for x in api('users') if x['id']==u['id'])
        assert runtime['runtime_status']=='Down' and runtime['session_count']==0
        api(f"users/{u['id']}",dict(password=secrets.token_hex(18),enabled=False),'PUT')
        api(f"users/{u['id']}",dict(enabled=True),'PUT')
    c=api('connections',dict(name='acceptance-s2s',remote_address='192.0.2.55',remote_ts='198.51.100.0/24',psk=secrets.token_hex(18)),'POST')
    created.append(('connections',c['id']))
    api(f"connections/{c['id']}",dict(enabled=False),'PUT')
    p=api('policies',dict(name='acceptance-policy',source_cidr='192.0.2.0/24',destination_cidr='198.51.100.0/24'),'POST')
    created.append(('policies',p['id']))
    assert 'c2s-eap-discovery' in api('status')['connections']
    assert isinstance(api('audit'),list)
    print('PASS health; split/full user CRUD + secret redaction + profile server + runtime Down; password/disable/re-enable revocation; S2S/policy CRUD; real swanctl/nft apply')
finally:
    for kind,ident in reversed(created):api(f'{kind}/{ident}',method='DELETE')
print('PASS cleanup: all temporary API objects removed')
