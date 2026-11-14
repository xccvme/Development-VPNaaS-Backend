import sqlite3, os, json, re, ipaddress, threading
from fastapi import HTTPException
lock=threading.RLock()
db=sqlite3.connect(os.environ.get('VPNAAS_DB','/opt/vpnaas/data.sqlite3'),check_same_thread=False)
db.execute('CREATE TABLE IF NOT EXISTS objects (kind TEXT,id INTEGER PRIMARY KEY AUTOINCREMENT, body TEXT)')
db.execute('CREATE TABLE IF NOT EXISTS audit (id INTEGER PRIMARY KEY, timestamp TEXT DEFAULT CURRENT_TIMESTAMP, action TEXT, resource TEXT, resource_id INTEGER)')

SCHEMA_VERSION=1
TRAFFIC_MODES=('split','full')

def migrate(conn):
    """v1: every user row carries traffic_mode; legacy rows become split."""
    if conn.execute('PRAGMA user_version').fetchone()[0]>=SCHEMA_VERSION:return
    for ident,body in conn.execute("SELECT id,body FROM objects WHERE kind='users'").fetchall():
        data=json.loads(body)
        if 'traffic_mode' not in data:
            data['traffic_mode']='split'
            conn.execute('UPDATE objects SET body=? WHERE id=?',(json.dumps(data),ident))
    conn.execute(f'PRAGMA user_version={SCHEMA_VERSION}')
    conn.commit()

db.commit()
migrate(db)

def rows(kind):
    return [dict(json.loads(b),id=i) for i,b in db.execute('SELECT id,body FROM objects WHERE kind=? ORDER BY id',(kind,))]
def get(kind,ident):
    for r in rows(kind):
        if r['id']==ident:return r
    raise HTTPException(404,'Not found')
def public(row):
    result = {k:v for k,v in row.items() if k not in ('password','psk')}
    if 'username' in row:result['traffic_mode']=row.get('traffic_mode','split')
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
    fields={'connections':{'name','remote_address','remote_id','local_ts','remote_ts','psk','enabled'},'users':{'username','password','enabled','allowed_cidrs','traffic_mode'},'policies':{'name','source_cidr','destination_cidr','protocol','enabled'}}[kind]
    if set(body)-fields:raise HTTPException(422,'Unknown fields')
    if kind=='users' and 'traffic_mode' in body and body['traffic_mode'] not in TRAFFIC_MODES:
        raise HTTPException(422,'traffic_mode must be split or full')
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
            data['allowed_cidrs']=[cidr(x) for x in data.get('allowed_cidrs',[os.environ.get('VPNAAS_LAN_CIDR','10.10.7.0/24')])]
            if not 0<len(data['allowed_cidrs'])<=16:raise ValueError()
            # 0/0 is expressed by traffic_mode=full, never as a LAN grant.
            if any(c.endswith('/0') for c in data['allowed_cidrs']):raise ValueError()
            data.setdefault('traffic_mode','split')
            if data['traffic_mode'] not in TRAFFIC_MODES:raise ValueError()
        else:
            data['name']=safe(data['name']);data['source_cidr']=cidr(data['source_cidr']);data['destination_cidr']=cidr(data['destination_cidr'])
            data.setdefault('protocol','all')
            if data['protocol'] not in ('all','tcp','udp','icmp'):raise ValueError()
    except (KeyError,ValueError,TypeError):raise HTTPException(422,'Invalid fields; credentials must be 8-128 safe printable characters')
    unique='username' if kind=='users' else 'name'
    if any(x[unique]==data[unique] and x['id']!=old.get('id') for x in rows(kind)):raise HTTPException(409,'Name already exists')
    return data
