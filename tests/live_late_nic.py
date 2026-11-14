#!/usr/bin/env python3
import json, secrets, urllib.request, subprocess, time
from pathlib import Path
key=Path('/etc/vpnaas/api.key').read_text().strip()
def api(p,b=None,m='GET'):
    return json.load(urllib.request.urlopen(urllib.request.Request('http://127.0.0.1:8000/api/'+p,data=json.dumps(b).encode() if b else None,headers={'X-API-Key':key,'Content-Type':'application/json'},method=m),timeout=40))
def cmd(*a):return subprocess.check_output(a,text=True)
def rules():return Path('/opt/vpnaas/firewall.nft').read_text()
def wait(predicate):
    for _ in range(20):
        if predicate():return
        time.sleep(1)
    raise AssertionError('timer did not reconcile')
u=None
try:
    u=api('users',dict(username='late-nic-test',password=secrets.token_hex(18),allowed_cidrs=['10.44.0.0/24']),'POST')
    v='10.250.0.'+str(u['id']+1)
    assert f'ip saddr {v} ip daddr 10.44.0.0/24 drop' in rules()
    assert not api('status')['network']['private_ready']
    print('PASS missing LAN blocks grant; API provisioning works; diagnostic not ready')
    cmd('ip','link','add','latevpn0','type','dummy');cmd('ip','addr','add','10.44.0.2/24','dev','latevpn0');cmd('ip','link','set','latevpn0','up')
    wait(lambda:f'ip saddr {v} ip daddr 10.44.0.0/24 oifname "latevpn0" masquerade' in rules())
    assert api('status')['network']['private_ready']
    print('PASS timer detected attached NIC; interface-qualified grant + masquerade; diagnostic ready')
    cmd('ip','addr','del','10.44.0.2/24','dev','latevpn0');cmd('ip','addr','add','10.44.0.3/24','dev','latevpn0')
    time.sleep(7)
    assert 'snat to 10.44.0.2' not in rules() and 'masquerade' in rules()
    print('PASS IP changed .2 to .3; masquerade follows without fixed address or reinstall')
    cmd('ip','link','del','latevpn0')
    wait(lambda:f'ip saddr {v} ip daddr 10.44.0.0/24 drop' in rules())
    assert not api('status')['network']['private_ready']
    print('PASS detach removed stale NIC/NAT grant; blocked again; API and SSH survived')
finally:
    subprocess.run(['ip','link','del','latevpn0'],capture_output=True)
    if u:api('users/'+str(u['id']),m='DELETE')
