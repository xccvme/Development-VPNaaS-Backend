"""Persistent server pool selection and ID-independent host leases."""
import ipaddress
import json
import os
from pathlib import Path
import secrets
import subprocess
import threading
try:
    import fcntl
except ImportError:  # pragma: no cover - non-POSIX dev hosts
    fcntl = None

_LOCAL_LOCK = threading.Lock()


def network():
    raw = os.environ.get('VPNAAS_POOL_CIDR', '172.31.201.0/24')
    net = ipaddress.IPv4Network(raw)
    if os.environ.get('VPNAAS_POOL_ALLOW_CUSTOM') == '1':
        if not net.is_private or not 20 <= net.prefixlen <= 24:
            raise ValueError('Custom VPNAAS_POOL_CIDR must be private IPv4 /20../24')
        return net
    if net.prefixlen != 24 or not net.subnet_of(ipaddress.ip_network('172.31.0.0/16')) or not 201 <= int(str(net.network_address).split('.')[2]) <= 250:
        raise ValueError('VPNAAS_POOL_CIDR must be 172.31.201..250.0/24')
    return net


def choose(occupied):
    nets=[ipaddress.ip_network(x,strict=False) for x in occupied if x not in ('default','0.0.0.0/0')]
    candidates=[f'172.31.{n}.0/24' for n in range(201,251) if not any(ipaddress.ip_network(f'172.31.{n}.0/24').overlaps(x) for x in nets if x.version==4)]
    if not candidates:raise ValueError('No conflict-free server VIP pool remains')
    return secrets.choice(candidates)


def ensure(path,occupied):
    path=Path(path)
    lock=path.with_suffix('.pool.lock')
    with _LOCAL_LOCK, lock.open('a') as handle:
        try:
            os.chmod(lock,0o600)
        except OSError:
            pass
        if fcntl is not None:
            fcntl.flock(handle,fcntl.LOCK_EX)
        text=path.read_text() if path.exists() else ''
        for line in text.splitlines():
            if line.startswith('VPNAAS_POOL_CIDR='):
                value=line.split('=',1)[1]
                old=os.environ.get('VPNAAS_POOL_CIDR')
                try:
                    os.environ['VPNAAS_POOL_CIDR']=value
                    network()
                finally:
                    if old is None:os.environ.pop('VPNAAS_POOL_CIDR',None)
                    else:os.environ['VPNAAS_POOL_CIDR']=old
                return value
        value=choose(occupied)
        temporary=path.with_suffix('.pool.tmp')
        fd=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_TRUNC,0o600)
        with os.fdopen(fd,'w') as f:
            f.write(text.rstrip()+'\nVPNAAS_POOL_CIDR='+value+'\n');f.flush();os.fsync(f.fileno())
        os.replace(temporary,path)
        return value


def leased(users):
    """Every persisted VIP: primary plus per-session extras."""
    return {v for u in users for v in [u.get('virtual_ip'),*u.get('extra_virtual_ips',[])] if v}


def allocate_many(users,count):
    from fastapi import HTTPException
    net = network()
    usable = max(0, net.num_addresses - 2)
    used=leased(users);result=[]
    for host in net.hosts():
        if len(result)==count:break
        if str(host) not in used:result.append(str(host))
    if len(result)<count:raise HTTPException(409,f'VIP pool exhausted ({usable} usable hosts; each session slot needs one)')
    return result


def allocate(users):
    return allocate_many(users,1)[0]


def size_extras(data,others):
    """Keep existing extra session VIPs (stable), trim or add up to max_sessions-1."""
    extras=list(data.get('extra_virtual_ips',[]))[:max(0,data['max_sessions']-1)]
    need=data['max_sessions']-1-len(extras)
    if need>0:extras+=allocate_many([*others,{'virtual_ip':data['virtual_ip'],'extra_virtual_ips':extras}],need)
    return extras


def migrate(conn):
    users=[(i,json.loads(b)) for i,b in conn.execute("SELECT id,body FROM objects WHERE kind='users' ORDER BY id")]
    used=set()
    for _,u in users:
        value=u.get('virtual_ip')
        if value:
            addr=ipaddress.IPv4Address(value)
            if addr not in network() or addr in (network().network_address,network().broadcast_address) or value in used:
                raise ValueError('Invalid or duplicate VIP; explicit backed-up migration required')
            used.add(value)
        for value in u.get('extra_virtual_ips',[]):
            addr=ipaddress.IPv4Address(value)
            if addr not in network() or addr in (network().network_address,network().broadcast_address) or value in used:
                raise ValueError('Invalid or duplicate session VIP; explicit backed-up migration required')
            used.add(value)
    for i,u in users:
        if not u.get('virtual_ip'):
            u['virtual_ip']=allocate([{'virtual_ip':v} for v in used]);used.add(u['virtual_ip'])
            conn.execute('UPDATE objects SET body=? WHERE id=?',(json.dumps(u),i))
    # One VIP per concurrent session slot. Never churn existing leases; if the
    # pool cannot supply a slot, clamp max_sessions instead of failing start-up.
    for i,u in users:
        limit=u.get('max_sessions',3)
        extras=list(u.get('extra_virtual_ips',[]))
        for value in extras[max(0,limit-1):]:used.discard(value)
        extras=extras[:max(0,limit-1)]
        while len(extras)<limit-1:
            free=next((str(h) for h in network().hosts() if str(h) not in used),None)
            if free is None:
                limit=1+len(extras)
                print(f'VIP pool full: user {i} max_sessions clamped to {limit}')
                break
            extras.append(free);used.add(free)
        if extras!=u.get('extra_virtual_ips') or limit!=u.get('max_sessions'):
            u['extra_virtual_ips']=extras;u['max_sessions']=limit
            conn.execute('UPDATE objects SET body=? WHERE id=?',(json.dumps(u),i))
    conn.commit()


if __name__=='__main__':
    path=Path('/etc/vpnaas/backend.env')
    routes=json.loads(subprocess.check_output(['ip','-j','-4','route','show','table','all']))
    occupied=[r['dst'] for r in routes if r.get('dst') and r['dst']!='default']
    # Other engines/administratively configured strongSwan pools may not be in DB.
    import re
    result=subprocess.run(['swanctl','--list-pools'],capture_output=True,text=True)
    if result.returncode:raise SystemExit('Cannot inspect existing strongSwan pools safely')
    occupied.extend(re.findall(r'(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?',result.stdout))
    ip=r'(?:\d{1,3}\.){3}\d{1,3}'
    for first,last in re.findall('('+ip+r')\s*(?:-|\.\.)\s*('+ip+')',result.stdout):
        occupied.extend(str(n) for n in ipaddress.summarize_address_range(ipaddress.IPv4Address(first),ipaddress.IPv4Address(last)))
    env=dict(l.split('=',1) for l in path.read_text().splitlines() if '=' in l)
    if env.get('VPNAAS_LAN_CIDR'):occupied.append(env['VPNAAS_LAN_CIDR'])
    import sqlite3
    db=Path(env.get('VPNAAS_DB','/var/lib/vpnaas/data.sqlite3'))
    if db.exists():
        conn=sqlite3.connect(db)
        for kind,body in conn.execute('SELECT kind,body FROM objects'):
            u=json.loads(body)
            occupied.extend(u.get('allowed_cidrs',[]))
            occupied.extend(x.strip() for k in ('local_ts','remote_ts','source_cidr','destination_cidr','subnets') if k in u for x in str(u[k]).split(',') if x.strip())
            for side in ('site_a','site_b'):
                if isinstance(u.get(side),dict) and u[side].get('subnets'):
                    occupied.extend(x.strip() for x in str(u[side]['subnets']).split(',') if x.strip())
            if u.get('virtual_ip'):occupied.append(u['virtual_ip']+'/32')
            for ev in u.get('extra_virtual_ips',[]):
                if ev:occupied.append(ev+'/32')
        conn.close()
    print('Server VIP pool: '+ensure(path,occupied))
