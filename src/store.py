import sqlite3, os, json, re, ipaddress, threading
from fastapi import HTTPException
lock=threading.RLock()
db=sqlite3.connect(os.environ.get('VPNAAS_DB','/opt/vpnaas/data.sqlite3'),check_same_thread=False)
db.execute('CREATE TABLE IF NOT EXISTS objects (kind TEXT,id INTEGER PRIMARY KEY AUTOINCREMENT, body TEXT)')
db.execute('CREATE TABLE IF NOT EXISTS audit (id INTEGER PRIMARY KEY, timestamp TEXT DEFAULT CURRENT_TIMESTAMP, action TEXT, resource TEXT, resource_id INTEGER)')

SCHEMA_VERSION=2
TRAFFIC_MODES=('split','full')
MAX_SESSIONS=3
DEFAULT_MAX_SESSIONS=3
# Installer placeholder used when no private NIC existed at install time.
LAN_PLACEHOLDER='192.0.2.0/24'
VIRTUAL_DEV=re.compile(r'^(docker|br-|veth|virbr|lo$|cni|flannel|cali|vpnaas)')

def default_lan_cidrs():
    """Default grant for a new user that omits allowed_cidrs.

    Prefer the configured LAN; when the installer only had the placeholder
    (private NIC attached later), use private LANs currently attached to a
    non-public, non-container interface. Never guess when none exist.
    """
    configured=os.environ.get('VPNAAS_LAN_CIDR','10.10.7.0/24')
    if configured!=LAN_PLACEHOLDER:return [configured]
    try:
        from network import snapshot,public_interface
        routes=snapshot();public=public_interface(routes)
    except Exception:routes,public=[],None
    from pool import network as pool_network
    try:pool=pool_network()
    except Exception:pool=None
    found=[]
    for r in routes:
        dev=r.get('dev') or ''
        if r.get('dst','default')=='default' or r.get('protocol')!='kernel' or 'linkdown' in (r.get('flags') or []):continue
        if not dev or dev==public or VIRTUAL_DEV.match(dev):continue
        try:net=ipaddress.IPv4Network(r['dst'])
        except ValueError:continue
        if not net.is_private or (pool and net.overlaps(pool)) or str(net) in found:continue
        found.append(str(net))
    if not found:raise HTTPException(422,'allowed_cidrs wajib: belum ada LAN privat terdeteksi di server')
    return found[:16]

def migrate(conn):
    """v1: users carry traffic_mode (legacy split). v2: users carry max_sessions (legacy 3)."""
    if conn.execute('PRAGMA user_version').fetchone()[0]>=SCHEMA_VERSION:return
    for ident,body in conn.execute("SELECT id,body FROM objects WHERE kind='users'").fetchall():
        data=json.loads(body)
        changed=False
        if 'traffic_mode' not in data:
            data['traffic_mode']='split';changed=True
        if 'max_sessions' not in data:
            data['max_sessions']=DEFAULT_MAX_SESSIONS;changed=True
        if changed:
            conn.execute('UPDATE objects SET body=? WHERE id=?',(json.dumps(data),ident))
    conn.execute(f'PRAGMA user_version={SCHEMA_VERSION}')
    conn.commit()

db.commit()
migrate(db)
from pool import migrate as migrate_pool
migrate_pool(db)

def rows(kind):
    return [dict(json.loads(b),id=i) for i,b in db.execute('SELECT id,body FROM objects WHERE kind=? ORDER BY id',(kind,))]
def get(kind,ident):
    for r in rows(kind):
        if r['id']==ident:return r
    raise HTTPException(404,'Not found')
def public(row):
    result = {k:v for k,v in row.items() if k not in ('password','psk')}
    if 'username' in row:
        result['traffic_mode']=row.get('traffic_mode','split')
        result['max_sessions']=row.get('max_sessions',DEFAULT_MAX_SESSIONS)
    return result
def audit(action,kind,ident):
    db.execute('INSERT INTO audit(action,resource,resource_id) VALUES(?,?,?)',(action,kind,ident))
def safe(value):
    if not isinstance(value,str) or not re.fullmatch(r'[A-Za-z0-9_@.:-]{1,128}',value):raise ValueError()
    return value
def cidr(value):return str(ipaddress.IPv4Network(value,strict=False))
def credential(value):
    if not isinstance(value,str) or not re.fullmatch(r'[A-Za-z0-9_@.!+,:/=-]{8,128}',value):raise ValueError()
    return value

def validate(kind,body,old=None):
    old=old or {}
    fields={'connections':{'name','remote_address','remote_id','local_ts','remote_ts','psk','enabled'},'users':{'username','password','enabled','allowed_cidrs','traffic_mode','max_sessions'},'policies':{'name','source_cidr','destination_cidr','protocol','enabled'}}[kind]
    if set(body)-fields:raise HTTPException(422,'Unknown fields')
    if kind=='users' and 'traffic_mode' in body and body['traffic_mode'] not in TRAFFIC_MODES:
        raise HTTPException(422,'traffic_mode must be split or full')
    if kind=='users' and 'max_sessions' in body:
        value=body['max_sessions']
        # bool is an int subclass; JSON true/false or 2.0 must not pass as a limit.
        if type(value) is not int or not 1<=value<=MAX_SESSIONS:
            raise HTTPException(422,f'max_sessions must be an integer 1..{MAX_SESSIONS}')
    data={k:v for k,v in old.items() if k!='id'}
    data.update({k:v for k,v in body.items() if not (k in ('psk','password') and not v)})
    try:
        data.setdefault('enabled',True)
        if type(data['enabled']) is not bool:raise ValueError()
        if kind=='connections':
            data['name']=safe(data['name']);data['remote_address']=str(ipaddress.IPv4Address(data['remote_address']))
            data['remote_id']=safe(data.get('remote_id') or data['remote_address'])
            data['local_ts']=cidr(data.get('local_ts',os.environ.get('VPNAAS_LAN_CIDR','10.10.7.0/24')));data['remote_ts']=cidr(data['remote_ts']);data['psk']=credential(data['psk'])
        elif kind=='users':
            data['username']=safe(data['username']);data['password']=credential(data['password'])
            if 'allowed_cidrs' not in data:data['allowed_cidrs']=default_lan_cidrs()
            data['allowed_cidrs']=[cidr(x) for x in data['allowed_cidrs']]
            if not 0<len(data['allowed_cidrs'])<=16:raise ValueError()
            # 0/0 is expressed by traffic_mode=full, never as a LAN grant.
            if any(c.endswith('/0') for c in data['allowed_cidrs']):raise ValueError()
            data.setdefault('traffic_mode','split')
            data.setdefault('max_sessions',DEFAULT_MAX_SESSIONS)
            if type(data['max_sessions']) is not int or not 1<=data['max_sessions']<=MAX_SESSIONS:raise ValueError()
            others=[r for r in rows('users') if r['id']!=old.get('id')]
            if 'virtual_ip' not in data:
                from pool import allocate
                data['virtual_ip']=allocate(others)
            from pool import size_extras
            data['extra_virtual_ips']=size_extras(data,others)
            if data['traffic_mode'] not in TRAFFIC_MODES:raise ValueError()
        else:
            data['name']=safe(data['name']);data['source_cidr']=cidr(data['source_cidr']);data['destination_cidr']=cidr(data['destination_cidr'])
            data.setdefault('protocol','all')
            if data['protocol'] not in ('all','tcp','udp','icmp'):raise ValueError()
    except (KeyError,ValueError,TypeError):raise HTTPException(422,'Invalid fields; credentials must be 8-128 safe printable characters')
    unique='username' if kind=='users' else 'name'
    if any(x[unique]==data[unique] and x['id']!=old.get('id') for x in rows(kind)):raise HTTPException(409,'Name already exists')
    return data
