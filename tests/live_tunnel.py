#!/usr/bin/env python3
"""Isolated on-gateway IKEv2/full dataplane acceptance; root only. No credentials printed."""
import json, os, subprocess, time, urllib.request, shutil
from pathlib import Path

BASE=Path('/etc/swanctl/acceptance-probe')
NS='vpncheck'
VETH='vpnc-host'
SOCK='/run/charon.vpncheck.vici'
key=Path('/etc/vpnaas/api.key').read_text().strip()
def api(path,body=None,method='GET'):
    req=urllib.request.Request('http://127.0.0.1:8000/api/'+path,data=json.dumps(body).encode() if body else None,headers={'X-API-Key':key,'Content-Type':'application/json'},method=method)
    return json.load(urllib.request.urlopen(req,timeout=45))
def run(*args,check=True):
    p=subprocess.run(args,text=True,capture_output=True,timeout=45)
    if check and p.returncode:raise RuntimeError('Failed: '+' '.join(args)+'\n'+p.stdout+p.stderr)
    return p.stdout+p.stderr

def swan(*args,check=True):return run('ip','netns','exec',NS,'swanctl',*args,'--uri','unix://'+SOCK,check=check)
user=None;proc=None
try:
    BASE.mkdir(mode=0o700)
    user=api('users',{'username':'acceptance-tunnel','password':__import__('secrets').token_hex(18),'allowed_cidrs':[os.environ.get('PROBE_LAN_CIDR','192.0.2.0/24')],'traffic_mode':'full'},'POST')
    profile=api(f"users/{user['id']}/profile")
    run('ip','netns','add',NS)
    run('ip','link','add',VETH,'type','veth','peer','name','vpnc-peer')
    run('ip','link','set','vpnc-peer','netns',NS)
    run('ip','addr','add','172.31.254.1/30','dev',VETH)
    run('ip','link','set',VETH,'up')
    run('ip','-n',NS,'addr','add','172.31.254.2/30','dev','vpnc-peer')
    run('ip','-n',NS,'link','set','vpnc-peer','up')
    run('ip','-n',NS,'link','set','lo','up')
    run('ip','-n',NS,'route','add','default','via','172.31.254.1')
    (BASE/'x509ca').mkdir()
    (BASE/'x509ca'/'ca.pem').write_text(profile['ca_certificate'])
    (BASE/'strongswan.conf').write_text('''charon-systemd {
 load_modular = yes
 pid_file = /run/charon.vpncheck.pid
 plugins {
  include /etc/strongswan.d/charon/*.conf
  vici { socket = unix:///run/charon.vpncheck.vici }
  resolve { load = no }
 }
 journal { default = 1 }
}
swanctl { plugins { include /etc/strongswan.d/charon/*.conf } }
''')
    (BASE/'swanctl.conf').write_text('''connections {
 check {
 version = 2
 remote_addrs = '''+profile['server']+'''
 vips = 0.0.0.0
 proposals = aes256-sha256-modp2048
 encap = yes
 local { auth = eap-mschapv2
 id = 172.31.254.2
 eap_id = acceptance-tunnel
 }
 remote { auth = pubkey
 id = '''+profile['server_id']+'''
 cacerts = ca.pem
 }
 children { check-net {
 local_ts = dynamic
 remote_ts = 0.0.0.0/0
 esp_proposals = aes256-sha256
 } }
 }
}
secrets { eap-check { id = acceptance-tunnel
 secret = "'''+profile['password']+'''"
} }
''')
    env=dict(os.environ,STRONGSWAN_CONF=str(BASE/'strongswan.conf'))
    with (BASE/'daemon.log').open('w') as log:
        proc=subprocess.Popen(['ip','netns','exec',NS,'/usr/sbin/charon-systemd'],env=env,stdout=log,stderr=log)
    for _ in range(50):
        if Path(SOCK).exists():break
        time.sleep(.1)
    print(swan('--load-all','--file',str(BASE/'swanctl.conf')))
    print(swan('--list-conns'))
    print(swan('--initiate','--child','check-net','--timeout','20'))
    runtime=next(x for x in api('users') if x['id']==user['id'])
    assert runtime['runtime_status']=='Active' and runtime['session_count']==1,runtime
    print('PASS runtime Active, authenticated EAP ID differs from IKE IDi')
    print(run('ip','netns','exec',NS,'ping','-c','3','-W','3','1.1.1.1'))
    egress=run('ip','netns','exec',NS,'curl','-4','--noproxy','*','--resolve','ifconfig.me:443:34.160.111.145','--max-time','25','-sS','https://ifconfig.me/ip').strip()
    assert egress==profile['server'],egress
    print('PASS full HTTPS public egress '+egress)
    if os.environ.get('PROBE_LAN_TARGET'):
        print(run('ip','netns','exec',NS,'ping','-I',profile['virtual_ip'],'-c','3','-W','3',os.environ['PROBE_LAN_TARGET']))
        print('PASS forwarded LAN target via negotiated VIP')
    print(swan('--list-sas'))
    api(f"users/{user['id']}",{'enabled':False},'PUT')
    runtime=next(x for x in api('users') if x['id']==user['id'])
    assert runtime['runtime_status']=='Down',runtime
    print('PASS live revocation: disable removed server SA; runtime Down')
finally:
    if proc:
        proc.terminate()
        try:proc.wait(timeout=10)
        except subprocess.TimeoutExpired:proc.kill();proc.wait()
    run('ip','netns','del',NS,check=False)
    run('ip','link','del',VETH,check=False)
    if user:api(f"users/{user['id']}",method='DELETE')
    shutil.rmtree(BASE,ignore_errors=True)
    Path(SOCK).unlink(missing_ok=True)
    Path('/run/charon.vpncheck.pid').unlink(missing_ok=True)
    print('Probe namespace, account, daemon and credential files cleaned')
