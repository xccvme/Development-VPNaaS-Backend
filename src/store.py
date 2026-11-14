import sqlite3, os, json, re, ipaddress, threading, secrets
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
    if 'site_a' in row or 'remote_address' in row:
        result['topology']=row.get('topology','direct')
        for side in SITES:
            if isinstance(row.get(side),dict):
                site=row[side]
                result[side]=dict({k:v for k,v in site.items() if k!='psk'},psk_set=bool(site.get('psk')))
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
MAX_TS=8
def ts_list(value):
    """S2S selector: comma-separated 1..MAX_TS IPv4 CIDRs, normalized, deduped, no /0."""
    if not isinstance(value,str):raise ValueError()
    result=[]
    for part in value.split(','):
        net=cidr(part.strip())
        if net.endswith('/0'):raise ValueError()
        if net not in result:result.append(net)
    if not 0<len(result)<=MAX_TS:raise ValueError()
    return result
def ts_split(value):
    """Persisted selector string (single legacy CIDR or comma list) -> list."""
    return [x.strip() for x in str(value).split(',') if x.strip()]
def check_selectors(local,remote):
    nets=lambda xs:[ipaddress.IPv4Network(x) for x in xs]
    if any(a.overlaps(b) for a in nets(local) for b in nets(remote)):
        raise HTTPException(422,'local_ts dan remote_ts tidak boleh overlap')
    from pool import network as pool_network
    try:pool=pool_network()
    except Exception:pool=None
    if pool and any(n.overlaps(pool) for n in nets(local+remote)):
        raise HTTPException(422,'local_ts/remote_ts tidak boleh overlap dengan pool VIP C2S')
def credential(value):
    if not isinstance(value,str) or not re.fullmatch(r'[A-Za-z0-9_@.!+,:/=-]{8,128}',value):raise ValueError()
    return value

TOPOLOGIES=('hub','direct')
SITES=('site_a','site_b')
DIRECT_FIELDS={'name','remote_address','remote_id','local_ts','remote_ts','psk','enabled','topology'}
HUB_FIELDS={'name','enabled','topology','site_a','site_b'}
SITE_FIELDS={'name','address','id','psk','subnets','nat'}
HOSTNAME=re.compile(r'(?=.{1,253}$)[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*')
SITE_NAME=re.compile(r'[A-Za-z0-9 _.@:()-]{1,64}')
HUB_PSK=re.compile(r'[A-Za-z0-9_@.!+,:/=-]{16,128}')

def topology_of(body,old):
    """Existing rows keep their topology (rows without the key are legacy 'direct').
    New rows: explicit value, else 'direct' when legacy fields are sent, else 'hub'."""
    if old:
        topology=old.get('topology','direct')
        if 'topology' in body and body['topology']!=topology:raise HTTPException(422,'topology tidak bisa diubah')
        return topology
    if 'topology' in body:
        if body['topology'] not in TOPOLOGIES:raise HTTPException(422,'topology harus hub atau direct')
        return body['topology']
    return 'direct' if set(body)&(DIRECT_FIELDS-HUB_FIELDS) else 'hub'

def slug(value):
    return re.sub(r'[^a-z0-9]+','-',str(value).lower()).strip('-') or 'hub'

def site_address(value):
    if value in (None,'','%any'):return '%any'
    if not isinstance(value,str):raise ValueError()
    try:return str(ipaddress.IPv4Address(value))
    except ValueError:pass
    if not HOSTNAME.fullmatch(value) or value.replace('.','').isdigit():raise ValueError()
    return value.lower()

def validate_hub(body,old):
    if set(body)-HUB_FIELDS:raise HTTPException(422,'Unknown fields')
    for side in SITES:
        if side in body and (not isinstance(body[side],dict) or set(body[side])-SITE_FIELDS):raise HTTPException(422,'Unknown fields')
    data={k:v for k,v in old.items() if k not in ('id',)+SITES}
    data.update({k:v for k,v in body.items() if k not in SITES})
    data['topology']='hub'
    data.setdefault('enabled',True)
    if type(data['enabled']) is not bool:raise HTTPException(422,'enabled harus boolean')
    try:data['name']=safe(data.get('name'))
    except ValueError:raise HTTPException(422,'name wajib: 1-128 karakter A-Z a-z 0-9 _ @ . : -')
    subnets={}
    for side,letter in zip(SITES,'ab'):
        site=dict(old.get(side) or {})
        site.update({k:v for k,v in (body.get(side) or {}).items() if not (k=='psk' and not v)})
        label='site_'+letter
        site.setdefault('name','Site '+letter.upper())
        if not isinstance(site['name'],str) or not SITE_NAME.fullmatch(site['name']):raise HTTPException(422,f'{label}.name tidak valid')
        try:site['address']=site_address(site.get('address'))
        except ValueError:raise HTTPException(422,f'{label}.address harus IPv4, hostname, atau %any')
        if not site.get('id'):site['id']=f"{slug(data['name'])}-{letter}@vpnaas"
        try:site['id']=safe(site['id'])
        except ValueError:raise HTTPException(422,f'{label}.id tidak valid (A-Z a-z 0-9 _ @ . : -)')
        if 'psk' not in site:site['psk']=secrets.token_urlsafe(24)
        if not isinstance(site['psk'],str) or not HUB_PSK.fullmatch(site['psk']):raise HTTPException(422,f'{label}.psk minimal 16 karakter aman')
        site.setdefault('nat',True)
        if type(site['nat']) is not bool:raise HTTPException(422,f'{label}.nat harus boolean')
        if 'subnets' not in site:raise HTTPException(422,f'{label}.subnets wajib')
        try:nets=ts_list(site['subnets'])
        except (ValueError,TypeError):raise HTTPException(422,f'{label}.subnets: 1-{MAX_TS} CIDR IPv4 dipisah koma, tanpa /0')
        site['subnets']=','.join(nets);subnets[side]=nets
        data[side]=site
    nets=lambda xs:[ipaddress.IPv4Network(x) for x in xs]
    if any(a.overlaps(b) for a in nets(subnets['site_a']) for b in nets(subnets['site_b'])):
        raise HTTPException(422,'subnets site_a dan site_b tidak boleh overlap')
    from pool import network as pool_network
    try:pool=pool_network()
    except Exception:pool=None
    if pool and any(n.overlaps(pool) for n in nets(subnets['site_a']+subnets['site_b'])):
        raise HTTPException(422,'subnets tidak boleh overlap dengan pool VIP C2S')
    if any(x['name']==data['name'] and x['id']!=old.get('id') for x in rows('connections')):raise HTTPException(409,'Name already exists')
    ida,idb=data['site_a']['id'],data['site_b']['id']
    taken=set()
    for r in rows('connections'):
        if r['id']==old.get('id'):continue
        taken.add(r.get('remote_id'))
        for side in SITES:taken.add((r.get(side) or {}).get('id'))
    if ida==idb or {ida,idb}&taken or os.environ.get('VPNAAS_PUBLIC_IP','203.0.113.10') in (ida,idb):
        raise HTTPException(422,'ID site harus unik di semua koneksi (dan berbeda dari ID hub)')
    return data

def validate(kind,body,old=None):
    old=old or {}
    if kind=='connections':
        if not isinstance(body,dict):raise HTTPException(422,'Invalid request')
        if topology_of(body,old)=='hub':return validate_hub(body,old)
        body={k:v for k,v in body.items() if k!='topology'}
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
            local=ts_list(data.get('local_ts',os.environ.get('VPNAAS_LAN_CIDR','10.10.7.0/24')));remote=ts_list(data['remote_ts'])
            hub_ids={(r.get(side) or {}).get('id') for r in rows('connections') if r['id']!=old.get('id') for side in SITES}
            if data['remote_id'] in hub_ids:raise HTTPException(422,'remote_id sudah dipakai sebagai ID site VPN Hub')
            data['local_ts']=','.join(local);data['remote_ts']=','.join(remote);data['psk']=credential(data['psk'])
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
    if kind=='connections':
        check_selectors(local,remote)
        if not old.get('id'):data['topology']='direct'
    unique='username' if kind=='users' else 'name'
    if any(x[unique]==data[unique] and x['id']!=old.get('id') for x in rows(kind)):raise HTTPException(409,'Name already exists')
    return data
