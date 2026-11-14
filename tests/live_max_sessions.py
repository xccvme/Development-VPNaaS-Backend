#!/usr/bin/env python3
"""Live per-account session-limit acceptance on the gateway; root only.

Creates a temporary user, starts N isolated client charon daemons (one netns
each, distinct source address), connects them one after another and watches
the server SAs. No credentials are printed. Only the temporary user, netns,
veths and probe files are removed; other users/connections are untouched.

Env: PROBE_CLIENTS (default 2), PROBE_MAX (default 1), PROBE_WAIT (default 15),
     PROBE_EXPECT=limit|observe|numeric (default limit). numeric uses max_sessions=3,
     terminates the newest server SA via `swanctl --terminate --ike-id N` and
     proves every other SA (other probe, site-30 etc.) keeps its IKE id.
"""
import json, os, subprocess, time, urllib.request, shutil, secrets
from pathlib import Path

N = int(os.environ.get('PROBE_CLIENTS', '2'))
MAX = int(os.environ.get('PROBE_MAX', '1'))
WAIT = int(os.environ.get('PROBE_WAIT', '15'))
EXPECT = os.environ.get('PROBE_EXPECT', 'limit')
USERNAME = 'acceptance-maxsess'
key = Path('/etc/vpnaas/api.key').read_text().strip()


def api(path, body=None, method='GET'):
    req = urllib.request.Request('http://127.0.0.1:8000/api/' + path,
                                 data=json.dumps(body).encode() if body is not None else None,
                                 headers={'X-API-Key': key, 'Content-Type': 'application/json'}, method=method)
    return json.load(urllib.request.urlopen(req, timeout=45))


def run(*args, check=True, env=None):
    p = subprocess.run(args, text=True, capture_output=True, timeout=45, env=env)
    if check and p.returncode:
        raise RuntimeError('Failed: ' + ' '.join(args) + '\n' + p.stdout + p.stderr)
    return p.stdout + p.stderr


def raw_sas():
    p = subprocess.run(['swanctl', '--list-sas', '--raw'], text=True, capture_output=True, timeout=20)
    from runtime import parse_sas
    return parse_sas(p.stdout)


def server_sas():
    sas = raw_sas()
    return [s for s in sas if s.get('remote-eap-id') == USERNAME]


def client(i):
    ns, veth, peer = f'vms{i}', f'vms{i}-h', f'vms{i}-p'
    base = Path(f'/etc/swanctl/maxsess-probe-{i}')
    sock = f'/run/charon.{ns}.vici'
    host_ip, peer_ip = f'172.31.253.{4*i+1}', f'172.31.253.{4*i+2}'
    return dict(i=i, ns=ns, veth=veth, peer=peer, base=base, sock=sock, host_ip=host_ip, peer_ip=peer_ip)


def start(c, profile):
    run('ip', 'netns', 'add', c['ns'])
    run('ip', 'link', 'add', c['veth'], 'type', 'veth', 'peer', 'name', c['peer'])
    run('ip', 'link', 'set', c['peer'], 'netns', c['ns'])
    run('ip', 'addr', 'add', c['host_ip'] + '/30', 'dev', c['veth'])
    run('ip', 'link', 'set', c['veth'], 'up')
    run('ip', '-n', c['ns'], 'addr', 'add', c['peer_ip'] + '/30', 'dev', c['peer'])
    run('ip', '-n', c['ns'], 'link', 'set', c['peer'], 'up')
    run('ip', '-n', c['ns'], 'link', 'set', 'lo', 'up')
    run('ip', '-n', c['ns'], 'route', 'add', 'default', 'via', c['host_ip'])
    base = c['base']
    base.mkdir(mode=0o700)
    (base / 'x509ca').mkdir()
    (base / 'x509ca' / 'ca.pem').write_text(profile['ca_certificate'])
    (base / 'strongswan.conf').write_text(f'''charon-systemd {{
 load_modular = yes
 pid_file = /run/charon.{c['ns']}.pid
 plugins {{
  include /etc/strongswan.d/charon/*.conf
  vici {{ socket = unix://{c['sock']} }}
  resolve {{ load = no }}
 }}
 journal {{ default = 1 }}
}}
swanctl {{ plugins {{ include /etc/strongswan.d/charon/*.conf }} }}
''')
    (base / 'swanctl.conf').write_text(f'''connections {{
 probe {{
 version = 2
 remote_addrs = {profile['server']}
 vips = 0.0.0.0
 proposals = aes256-sha256-modp2048
 encap = yes
 local {{ auth = eap-mschapv2
 id = {c['peer_ip']}
 eap_id = {USERNAME}
 }}
 remote {{ auth = pubkey
 id = {profile['server_id']}
 cacerts = ca.pem
 }}
 children {{ probe-net {{
 local_ts = dynamic
 remote_ts = {profile['allowed_cidrs'][0]}
 esp_proposals = aes256-sha256
 }} }}
 }}
}}
secrets {{ eap-probe {{ id = {USERNAME}
 secret = "{profile['password']}"
}} }}
''')
    env = dict(os.environ, STRONGSWAN_CONF=str(base / 'strongswan.conf'))
    log = (base / 'daemon.log').open('w')
    c['proc'] = subprocess.Popen(['ip', 'netns', 'exec', c['ns'], '/usr/sbin/charon-systemd'], env=env, stdout=log, stderr=log)
    for _ in range(50):
        if Path(c['sock']).exists():
            break
        time.sleep(.1)
    swan(c, '--load-all', '--file', str(base / 'swanctl.conf'))


def swan(c, *args, check=True):
    return run('ip', 'netns', 'exec', c['ns'], 'swanctl', *args, '--uri', 'unix://' + c['sock'], check=check)


def stop(c):
    proc = c.get('proc')
    if proc:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill(); proc.wait()
    run('ip', 'netns', 'del', c['ns'], check=False)
    run('ip', 'link', 'del', c['veth'], check=False)
    shutil.rmtree(c['base'], ignore_errors=True)
    Path(c['sock']).unlink(missing_ok=True)
    Path(f"/run/charon.{c['ns']}.pid").unlink(missing_ok=True)


def summary(sas):
    return [(s.get('uniqueid'), s.get('remote-host'), s.get('state'), s.get('remote-vips'),
             [ch.get('state') for ch in s.get('child-sas', {}).values()]) for s in sas]


baseline = {s.get('name'): s.get('uniqueid') for s in raw_sas()}
print('baseline SAs (name->ike id):', baseline)
user = None
clients = [client(i) for i in range(N)]
failed = False
try:
    body = {'username': USERNAME, 'password': secrets.token_hex(18),
            'allowed_cidrs': [os.environ.get('PROBE_LAN_CIDR', '192.0.2.0/24')]}
    if EXPECT == 'limit':
        body['max_sessions'] = MAX
    if EXPECT == 'numeric':
        body['max_sessions'] = 3
    user = api('users', body, 'POST')
    print('temp user id', user['id'], 'max_sessions', user.get('max_sessions'))
    profile = api(f"users/{user['id']}/profile")
    for c in clients:
        start(c, profile)
    first = None
    for c in clients:
        out = swan(c, '--initiate', '--child', 'probe-net', '--timeout', '20', check=False)
        c['initiated'] = time.time()
        ok = 'completed successfully' in out or 'established successfully' in out
        print(f"client {c['i']} ({c['peer_ip']}) initiate ok={ok}")
        if not ok:
            print('  tail:', ' | '.join(l for l in out.splitlines()[-4:]))
        print('  server SAs:', summary(server_sas()))
        if first is None and ok:
            first = next((s['uniqueid'] for s in server_sas() if s.get('remote-host') == c['peer_ip']), None)
        time.sleep(1)
    row = next(x for x in api('users') if x['id'] == user['id'])
    print('API after connects: session_count', row['session_count'], 'max_sessions', row.get('max_sessions'))
    deadline = time.time() + WAIT
    while time.time() < deadline:
        sas = [s for s in server_sas() if s.get('state') == 'ESTABLISHED']
        if EXPECT != 'observe' and EXPECT != 'numeric' and len(sas) <= MAX:
            break
        if EXPECT in ('observe', 'numeric'):
            break
        time.sleep(1)
    sas = server_sas()
    elapsed = time.time() - clients[-1]['initiated']
    print(f'server SAs after <= {WAIT}s (t+{elapsed:.1f}s from last connect):', summary(sas))
    for c in clients:
        print(f"client {c['i']} SAs:", ' '.join(l.strip() for l in swan(c, '--list-sas', check=False).splitlines() if 'ESTABLISHED' in l or 'INSTALLED' in l) or 'none')
    row = next(x for x in api('users') if x['id'] == user['id'])
    print('API final: session_count', row['session_count'], 'max_sessions', row.get('max_sessions'),
          'ike_ids', [s['ike_id'] for s in row['sessions']])
    if EXPECT == 'numeric':
        everything = {s['uniqueid']: s.get('name') for s in raw_sas()}
        mine = sorted((s['uniqueid'] for s in sas if s.get('state') == 'ESTABLISHED'), key=int)
        assert len(mine) == N, mine
        victim = mine[-1]
        print('terminate --ike-id', victim, '->', run('swanctl', '--terminate', '--ike-id', victim, '--force').strip().splitlines()[-1])
        time.sleep(2)
        left = {s['uniqueid']: s.get('name') for s in raw_sas()}
        expected = {k: v for k, v in everything.items() if k != victim}
        assert left == expected, (left, expected)
        print(f'PASS numeric termination removed only IKE #{victim}; remaining {left}')
    if EXPECT == 'limit':
        alive = [s['uniqueid'] for s in sas if s.get('state') == 'ESTABLISHED']
        assert alive == [first], (alive, first)
        print(f'PASS surplus terminated; original IKE #{first} alive')
    after = {s.get('name'): s.get('uniqueid') for s in raw_sas()}
    for name, ident in baseline.items():
        assert after.get(name) == ident, ('baseline SA changed', name, ident, after.get(name))
    print('PASS baseline SAs unchanged:', {k: after[k] for k in baseline})
except Exception as e:
    failed = True
    print('FAIL', repr(e)[:800])
finally:
    for c in clients:
        stop(c)
    if user:
        api(f"users/{user['id']}", method='DELETE')
    print('Probe namespaces, temp account, daemons and credential files cleaned')
raise SystemExit(1 if failed else 0)
