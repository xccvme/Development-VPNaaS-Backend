import sqlite3, os, json, re, ipaddress, threading, secrets
from fastapi import HTTPException
from auth import init_tokens_table

lock=threading.RLock()
db=sqlite3.connect(os.environ.get('VPNAAS_DB','/opt/vpnaas/data.sqlite3'),check_same_thread=False)
db.execute('CREATE TABLE IF NOT EXISTS objects (kind TEXT,id INTEGER PRIMARY KEY AUTOINCREMENT, body TEXT)')
db.execute('CREATE INDEX IF NOT EXISTS idx_objects_kind ON objects(kind)')
db.execute('CREATE TABLE IF NOT EXISTS audit (id INTEGER PRIMARY KEY, timestamp TEXT DEFAULT CURRENT_TIMESTAMP, action TEXT, resource TEXT, resource_id INTEGER)')
init_tokens_table(db)

SCHEMA_VERSION=3
TRAFFIC_MODES=('split','full')
AUTH_METHODS_USER=('eap-mschapv2','pubkey','eap-tls')
AUTH_METHODS_SITE=('psk','pubkey')
POLICY_ACTIONS=('allow','deny')
POLICY_SOURCE_TYPES=('cidr','site','user','group')
POLICY_DEST_TYPES=('cidr','site','vpc')
MAX_SESSIONS=3
DEFAULT_MAX_SESSIONS=3
# Installer placeholder used when no private NIC existed at install time.
LAN_PLACEHOLDER='192.0.2.0/24'
VIRTUAL_DEV=re.compile(r'^(docker|br-|veth|virbr|lo$|cni|flannel|cali|vpnaas)')
IFNAME_RE=re.compile(r'^[A-Za-z0-9_.:-]{1,15}$')
DESC_RE=re.compile(r'^[A-Za-z0-9 _.@:()/,+-]{0,256}$')

DEFAULT_IKE_PROPOSALS='aes256-sha256-modp2048,aes128-sha256-modp2048'
DEFAULT_ESP_PROPOSALS='aes256-sha256,aes128-sha256'
ALLOWED_IKE_TOKENS={
    'aes256-sha256-modp2048',
    'aes128-sha256-modp2048',
    'aes256-sha384-modp3072',
    'aes256-sha512-modp4096',
    'aes256-sha256-ecp256',
    'aes256-sha384-ecp384',
    'aes256gcm16-prfsha384-ecp384',
    'aes256gcm16-prfsha256-modp2048',
    'aes128gcm16-prfsha256-ecp256',
}
ALLOWED_ESP_TOKENS={
    'aes256-sha256',
    'aes128-sha256',
    'aes256-sha384',
    'aes256-sha256-modp2048',
    'aes256-sha384-modp3072',
    'aes256-sha256-ecp256',
    'aes256gcm16',
    'aes256gcm16-ecp384',
    'aes256gcm16-modp2048',
    'aes128gcm16',
}


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
    """v1: traffic_mode. v2: max_sessions. v3: auth_method/groups/allowed_sites defaults on users."""
    if conn.execute('PRAGMA user_version').fetchone()[0]>=SCHEMA_VERSION:return
    for ident,body in conn.execute("SELECT id,body FROM objects WHERE kind='users'").fetchall():
        data=json.loads(body)
        changed=False
        if 'traffic_mode' not in data:
            data['traffic_mode']='split';changed=True
        if 'max_sessions' not in data:
            data['max_sessions']=DEFAULT_MAX_SESSIONS;changed=True
        if 'auth_method' not in data:
            data['auth_method']='eap-mschapv2';changed=True
        if 'groups' not in data:
            data['groups']=[];changed=True
        if 'allowed_sites' not in data:
            data['allowed_sites']=[];changed=True
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
    row=db.execute('SELECT id,body FROM objects WHERE kind=? AND id=?',(kind,ident)).fetchone()
    if not row:raise HTTPException(404,'Not found')
    return dict(json.loads(row[1]),id=row[0])


def public(row):
    result = {k:v for k,v in row.items() if k not in ('password','psk','private_key_pem')}
    if 'site_a' in row or 'remote_address' in row:
        result['topology']=row.get('topology','direct')
        for side in SITES:
            if isinstance(row.get(side),dict):
                site=row[side]
                result[side]=dict({k:v for k,v in site.items() if k!='psk'},psk_set=bool(site.get('psk')))
    if 'ike_id' in row and 'subnets' in row:
        result['auth_method']=row.get('auth_method','psk')
        result['peer_sites']=row.get('peer_sites',[])
        if result['auth_method']=='psk':
            result['psk_set']=bool(row.get('psk'))
    if 'username' in row:
        result['traffic_mode']=row.get('traffic_mode','split')
        result['max_sessions']=row.get('max_sessions',DEFAULT_MAX_SESSIONS)
        result['auth_method']=row.get('auth_method','eap-mschapv2')
        result['groups']=row.get('groups',[])
        result['allowed_sites']=row.get('allowed_sites',[])
        if 'cert_id' in row:
            result['cert_id']=row['cert_id']
    if 'protocol' in row and ('source_cidr' in row or 'source_type' in row):
        result.setdefault('action','allow')
        result.setdefault('priority',100)
        result.setdefault('source_type','cidr')
        result.setdefault('destination_type','cidr')
    return result


def audit(action,kind,ident):
    db.execute('INSERT INTO audit(action,resource,resource_id) VALUES(?,?,?)',(action,kind,ident))


def safe(value):
    if not isinstance(value,str) or not re.fullmatch(r'[A-Za-z0-9_@.:-]{1,128}',value):raise ValueError()
    return value


def cidr(value):return str(ipaddress.IPv4Network(value,strict=False))


MAX_TS=8
MAX_SITE_TS=16


def ts_list(value,max_items=MAX_TS,allow_list=False):
    """S2S selector: comma-separated string (or list if allow_list=True) of 1..max_items IPv4 CIDRs, normalized, deduped, no /0."""
    if allow_list and isinstance(value,list):
        parts=value
    elif isinstance(value,str):
        parts=value.split(',')
    else:
        raise ValueError()
    result=[]
    for part in parts:
        if not isinstance(part,str):raise ValueError()
        net=cidr(part.strip())
        if net.endswith('/0'):raise ValueError()
        if net not in result:result.append(net)
    if not 0<len(result)<=max_items:raise ValueError()
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


def parse_ports(value):
    """Validate TCP/UDP port specification: '443', '80,443', '8000-8080', or list of ints/strings."""
    if value in (None,''):return None
    items=[]
    raw_items=value if isinstance(value,list) else (value.split(',') if isinstance(value,str) else None)
    if raw_items is None:raise HTTPException(422,'ports harus berupa string atau list port/range')
    for raw in raw_items:
        part=str(raw).strip()
        if not part:raise HTTPException(422,'Elemen ports tidak boleh kosong')
        if '-' in part:
            pieces=part.split('-')
            if len(pieces)!=2 or not all(p.isdigit() for p in pieces):
                raise HTTPException(422,'Range port tidak valid (contoh: 8000-8080)')
            lo,hi=int(pieces[0]),int(pieces[1])
            if not (1<=lo<=hi<=65535):raise HTTPException(422,'Port harus di rentang 1..65535')
            norm=f'{lo}-{hi}' if lo!=hi else str(lo)
        else:
            if not part.isdigit():raise HTTPException(422,'Port harus angka 1..65535')
            p=int(part)
            if not 1<=p<=65535:raise HTTPException(422,'Port harus di rentang 1..65535')
            norm=str(p)
        if norm not in items:items.append(norm)
    if not 0<len(items)<=16:raise HTTPException(422,'ports harus berisi 1..16 port/range')
    return ','.join(items)


def _validate_proposals(value,allowed,label):
    if not isinstance(value,str):raise HTTPException(422,f'{label} tidak valid')
    parts=[x.strip().lower() for x in value.split(',') if x.strip()]
    if not 1<=len(parts)<=4 or any(p not in allowed for p in parts):
        raise HTTPException(422,f'{label} hanya menerima preset kriptografi kuat yang diizinkan')
    dedup=[]
    for p in parts:
        if p not in dedup:dedup.append(p)
    return ','.join(dedup)


def _check_id_list(value,kind,label,max_items=32):
    if not isinstance(value,list) or len(value)>max_items:
        raise HTTPException(422,f'{label} harus berupa array ID integer (maks {max_items})')
    valid_ids={r['id'] for r in rows(kind)}
    out=[]
    for item in value:
        if type(item) is not int or item not in valid_ids:
            raise HTTPException(422,f'{label} memuat ID {kind} yang tidak ditemukan')
        if item not in out:out.append(item)
    return out


def _check_cert(cert_id,target_type):
    if type(cert_id) is not int:
        raise HTTPException(422,'cert_id harus berupa integer')
    try:
        cert=get('certs',cert_id)
    except HTTPException:
        raise HTTPException(422,'cert_id tidak ditemukan')
    if cert.get('revoked'):
        raise HTTPException(422,'Sertifikat sudah dicabut (revoked)')
    if cert.get('target_type')!=target_type:
        raise HTTPException(422,f'Sertifikat harus bertipe {target_type}')
    return cert_id


def site_effective_subnets(site,routes=None):
    """Ordered deduplicated subnets of a Multi-Site S2S peer (own subnets + enabled static routes attached to site_id)."""
    routes=rows('routes') if routes is None else routes
    out=[]
    def add(c):
        if c and c not in out:out.append(c)
    for c in ts_split(site.get('subnets','')):
        add(c)
    sid=site.get('id')
    if sid is not None:
        for r in routes:
            if r.get('enabled',True) and r.get('site_id')==sid:
                add(r.get('destination_cidr'))
    return out


def effective_user_cidrs(user,groups=None,sites=None,routes=None):
    """Ordered deduplicated CIDRs accessible by a C2S user (own CIDRs + groups + allowed_sites + site static routes)."""
    groups=rows('groups') if groups is None else groups
    sites=rows('sites') if sites is None else sites
    routes=rows('routes') if routes is None else routes
    gmap={g['id']:g for g in groups if g.get('enabled',True)}
    smap={s['id']:s for s in sites if s.get('enabled',True)}
    out=[]
    def add(c):
        if c and c not in out:out.append(c)
    for c in user.get('allowed_cidrs',[]):
        add(c)
    site_ids=list(user.get('allowed_sites',[]))
    for gid in user.get('groups',[]):
        g=gmap.get(gid)
        if not g:continue
        for c in g.get('allowed_cidrs',[]):
            add(c)
        for sid in g.get('allowed_sites',[]):
            if sid not in site_ids:site_ids.append(sid)
    for sid in site_ids:
        s=smap.get(sid)
        if not s:continue
        for c in site_effective_subnets(s,routes):
            add(c)
    return out


def effective_user_site_ids(user,groups=None):
    """Set of Multi-Site IDs granted to a user directly or via enabled groups."""
    groups=rows('groups') if groups is None else groups
    gmap={g['id']:g for g in groups if g.get('enabled',True)}
    sids=set(user.get('allowed_sites',[]))
    for gid in user.get('groups',[]):
        g=gmap.get(gid)
        if g:sids.update(g.get('allowed_sites',[]))
    return sids


TOPOLOGIES=('hub','direct')
SITES=('site_a','site_b')
DIRECT_FIELDS={'name','remote_address','remote_id','local_ts','remote_ts','psk','enabled','topology'}
HUB_FIELDS={'name','enabled','topology','site_a','site_b'}
SITE_FIELDS={'name','address','id','psk','subnets','nat'}
MULTI_SITE_FIELDS={'name','address','ike_id','auth_method','psk','cert_id','subnets','nat','dpd_delay','encap','ike_proposals','esp_proposals','allow_vpc','peer_sites','description','enabled'}
GROUP_FIELDS={'name','description','allowed_cidrs','allowed_sites','traffic_mode','max_sessions','enabled'}
ROUTE_FIELDS={'name','destination_cidr','gateway','interface','metric','site_id','description','enabled'}
POLICY_FIELDS={'name','source_cidr','destination_cidr','protocol','enabled','action','ports','priority','source_type','source_ref','destination_type','destination_ref','description'}
USER_FIELDS={'username','password','enabled','allowed_cidrs','traffic_mode','max_sessions','auth_method','groups','allowed_sites','cert_id'}

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


def _all_taken_ike_ids(exclude_kind=None,exclude_id=None):
    taken=set()
    for r in rows('connections'):
        if exclude_kind=='connections' and r['id']==exclude_id:continue
        if r.get('remote_id'):taken.add(r['remote_id'])
        for side in SITES:
            sid=(r.get(side) or {}).get('id')
            if sid:taken.add(sid)
    for r in rows('sites'):
        if exclude_kind=='sites' and r['id']==exclude_id:continue
        if r.get('ike_id'):taken.add(r['ike_id'])
    return taken


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
    taken=_all_taken_ike_ids('connections',old.get('id'))
    if ida==idb or {ida,idb}&taken or os.environ.get('VPNAAS_PUBLIC_IP','203.0.113.10') in (ida,idb):
        raise HTTPException(422,'ID site harus unik di semua koneksi (dan berbeda dari ID hub)')
    return data


def validate_site(body,old):
    if not isinstance(body,dict):raise HTTPException(422,'Invalid request')
    if set(body)-MULTI_SITE_FIELDS:raise HTTPException(422,'Unknown fields')
    data={k:v for k,v in old.items() if k!='id'}
    data.update({k:v for k,v in body.items() if not (k=='psk' and not v)})
    data.setdefault('enabled',True)
    if type(data['enabled']) is not bool:raise HTTPException(422,'enabled harus boolean')
    try:data['name']=safe(data.get('name'))
    except ValueError:raise HTTPException(422,'name wajib: 1-128 karakter A-Z a-z 0-9 _ @ . : -')
    try:data['address']=site_address(data.get('address'))
    except ValueError:raise HTTPException(422,'address harus IPv4, hostname, atau %any')
    if not data.get('ike_id'):data['ike_id']=f"{slug(data['name'])}@vpnaas"
    try:data['ike_id']=safe(data['ike_id'])
    except ValueError:raise HTTPException(422,'ike_id tidak valid (A-Z a-z 0-9 _ @ . : -)')
    data.setdefault('auth_method','psk')
    if data['auth_method'] not in AUTH_METHODS_SITE:
        raise HTTPException(422,'auth_method site harus psk atau pubkey')
    if data['auth_method']=='psk':
        if 'psk' not in data:data['psk']=secrets.token_urlsafe(24)
        if not isinstance(data['psk'],str) or not HUB_PSK.fullmatch(data['psk']):
            raise HTTPException(422,'psk minimal 16 karakter aman')
        data.pop('cert_id',None)
    else:
        if 'cert_id' not in data or data['cert_id'] is None:
            raise HTTPException(422,'cert_id wajib untuk auth_method pubkey')
        data['cert_id']=_check_cert(data['cert_id'],'site')
        data.pop('psk',None)
    if 'subnets' not in data:raise HTTPException(422,'subnets wajib')
    try:nets=ts_list(data['subnets'],max_items=MAX_SITE_TS,allow_list=True)
    except (ValueError,TypeError):raise HTTPException(422,f'subnets: 1-{MAX_SITE_TS} CIDR IPv4, tanpa /0')
    data['subnets']=','.join(nets)
    data.setdefault('nat',True)
    if type(data['nat']) is not bool:raise HTTPException(422,'nat harus boolean')
    data.setdefault('encap',True)
    if type(data['encap']) is not bool:raise HTTPException(422,'encap harus boolean')
    data.setdefault('allow_vpc',True)
    if type(data['allow_vpc']) is not bool:raise HTTPException(422,'allow_vpc harus boolean')
    peer_sites=_check_id_list(data.get('peer_sites',[]),'sites','peer_sites')
    if old.get('id') and old['id'] in peer_sites:
        raise HTTPException(422,'peer_sites tidak boleh menunjuk ke site ini sendiri')
    data['peer_sites']=peer_sites
    data.setdefault('dpd_delay',30)
    if type(data['dpd_delay']) is not int or not 10<=data['dpd_delay']<=300:
        raise HTTPException(422,'dpd_delay harus integer 10..300 detik')
    data['ike_proposals']=_validate_proposals(data.get('ike_proposals',DEFAULT_IKE_PROPOSALS),ALLOWED_IKE_TOKENS,'ike_proposals')
    data['esp_proposals']=_validate_proposals(data.get('esp_proposals',DEFAULT_ESP_PROPOSALS),ALLOWED_ESP_TOKENS,'esp_proposals')
    desc=data.get('description','')
    if not isinstance(desc,str) or not DESC_RE.fullmatch(desc):
        raise HTTPException(422,'description tidak valid')
    data['description']=desc

    my_nets=[ipaddress.IPv4Network(x) for x in nets]
    from pool import network as pool_network
    try:pool=pool_network()
    except Exception:pool=None
    if pool and any(n.overlaps(pool) for n in my_nets):
        raise HTTPException(422,'subnets tidak boleh overlap dengan pool VIP C2S')
    for other in rows('sites'):
        if other['id']==old.get('id'):continue
        other_nets=[ipaddress.IPv4Network(x) for x in ts_split(other.get('subnets',''))]
        if any(a.overlaps(b) for a in my_nets for b in other_nets):
            raise HTTPException(422,f"subnets overlap dengan site '{other['name']}'")
    taken=_all_taken_ike_ids('sites',old.get('id'))
    if data['ike_id'] in taken or data['ike_id']==os.environ.get('VPNAAS_PUBLIC_IP','203.0.113.10'):
        raise HTTPException(422,'ike_id harus unik di semua site/koneksi dan berbeda dari ID hub')
    if any(x['name']==data['name'] and x['id']!=old.get('id') for x in rows('sites')):
        raise HTTPException(409,'Name already exists')
    return data


def validate_group(body,old):
    if not isinstance(body,dict):raise HTTPException(422,'Invalid request')
    if set(body)-GROUP_FIELDS:raise HTTPException(422,'Unknown fields')
    data={k:v for k,v in old.items() if k!='id'}
    data.update(body)
    data.setdefault('enabled',True)
    if type(data['enabled']) is not bool:raise HTTPException(422,'enabled harus boolean')
    try:data['name']=safe(data.get('name'))
    except ValueError:raise HTTPException(422,'name wajib: 1-128 karakter A-Z a-z 0-9 _ @ . : -')
    desc=data.get('description','')
    if not isinstance(desc,str) or not DESC_RE.fullmatch(desc):
        raise HTTPException(422,'description tidak valid')
    data['description']=desc
    raw_cidrs=data.get('allowed_cidrs',[])
    if not isinstance(raw_cidrs,list) or len(raw_cidrs)>16:
        raise HTTPException(422,'allowed_cidrs harus array 0..16 CIDR IPv4')
    cidrs=[]
    for item in raw_cidrs:
        try:net=cidr(item)
        except Exception:raise HTTPException(422,'CIDR tidak valid di allowed_cidrs')
        if net.endswith('/0'):raise HTTPException(422,'allowed_cidrs tidak boleh berisi 0.0.0.0/0')
        if net not in cidrs:cidrs.append(net)
    data['allowed_cidrs']=cidrs
    data['allowed_sites']=_check_id_list(data.get('allowed_sites',[]),'sites','allowed_sites')
    if 'traffic_mode' in data and data['traffic_mode'] is not None:
        if data['traffic_mode'] not in TRAFFIC_MODES:
            raise HTTPException(422,'traffic_mode must be split or full')
    if 'max_sessions' in data and data['max_sessions'] is not None:
        val=data['max_sessions']
        if type(val) is not int or not 1<=val<=MAX_SESSIONS:
            raise HTTPException(422,f'max_sessions must be an integer 1..{MAX_SESSIONS}')
    if any(x['name']==data['name'] and x['id']!=old.get('id') for x in rows('groups')):
        raise HTTPException(409,'Name already exists')
    return data


def validate_route(body,old):
    if not isinstance(body,dict):raise HTTPException(422,'Invalid request')
    if set(body)-ROUTE_FIELDS:raise HTTPException(422,'Unknown fields')
    data={k:v for k,v in old.items() if k!='id'}
    data.update(body)
    data.setdefault('enabled',True)
    if type(data['enabled']) is not bool:raise HTTPException(422,'enabled harus boolean')
    try:data['name']=safe(data.get('name'))
    except ValueError:raise HTTPException(422,'name wajib: 1-128 karakter A-Z a-z 0-9 _ @ . : -')
    if 'destination_cidr' not in data:raise HTTPException(422,'destination_cidr wajib')
    try:dst=cidr(data['destination_cidr'])
    except Exception:raise HTTPException(422,'destination_cidr harus CIDR IPv4 valid')
    if dst.endswith('/0'):raise HTTPException(422,'destination_cidr tidak boleh 0.0.0.0/0')
    from pool import network as pool_network
    try:pool=pool_network()
    except Exception:pool=None
    if pool and ipaddress.IPv4Network(dst).overlaps(pool):
        raise HTTPException(422,'destination_cidr tidak boleh overlap dengan pool VIP C2S')
    data['destination_cidr']=dst

    gw=data.get('gateway')
    if gw in (None,''):
        data['gateway']=None
    else:
        try:
            addr=ipaddress.IPv4Address(gw)
            if addr==ipaddress.IPv4Address('0.0.0.0'):raise ValueError()
            data['gateway']=str(addr)
        except Exception:raise HTTPException(422,'gateway harus IPv4 valid')

    iface=data.get('interface')
    if iface in (None,''):
        data['interface']=None
    else:
        if not isinstance(iface,str) or not IFNAME_RE.fullmatch(iface) or iface=='lo':
            raise HTTPException(422,'interface tidak valid')
        data['interface']=iface

    site_id=data.get('site_id')
    if site_id is None:
        data['site_id']=None
    else:
        if type(site_id) is not int or not any(s['id']==site_id for s in rows('sites')):
            raise HTTPException(422,'site_id tidak ditemukan')
        data['site_id']=site_id

    if not data['gateway'] and not data['interface'] and data['site_id'] is None:
        raise HTTPException(422,'Minimal satu dari gateway, interface, atau site_id wajib diisi')

    data.setdefault('metric',100)
    if type(data['metric']) is not int or not 1<=data['metric']<=65535:
        raise HTTPException(422,'metric harus integer 1..65535')
    desc=data.get('description','')
    if not isinstance(desc,str) or not DESC_RE.fullmatch(desc):
        raise HTTPException(422,'description tidak valid')
    data['description']=desc

    if any(x['name']==data['name'] and x['id']!=old.get('id') for x in rows('routes')):
        raise HTTPException(409,'Name already exists')
    if any(x['destination_cidr']==data['destination_cidr'] and x['id']!=old.get('id') for x in rows('routes')):
        raise HTTPException(409,'Route untuk destination_cidr tersebut sudah ada')
    return data


def validate_policy(body,old):
    if set(body)-POLICY_FIELDS:raise HTTPException(422,'Unknown fields')
    data={k:v for k,v in old.items() if k!='id'}
    data.update(body)
    data.setdefault('enabled',True)
    if type(data['enabled']) is not bool:raise HTTPException(422,'Invalid fields; credentials must be 8-128 safe printable characters')
    try:data['name']=safe(data['name'])
    except (KeyError,ValueError,TypeError):raise HTTPException(422,'Invalid fields; credentials must be 8-128 safe printable characters')

    action=data.get('action','allow')
    if action not in POLICY_ACTIONS:raise HTTPException(422,'action harus allow atau deny')
    data['action']=action

    priority=data.get('priority',100)
    if type(priority) is not int or not 1<=priority<=10000:
        raise HTTPException(422,'priority harus integer 1..10000')
    data['priority']=priority

    protocol=data.get('protocol','all')
    if protocol not in ('all','tcp','udp','icmp'):
        raise HTTPException(422,'Invalid fields; credentials must be 8-128 safe printable characters')
    data['protocol']=protocol

    if data.get('ports') in (None,'') or (protocol not in ('tcp','udp') and 'ports' not in body):
        data.pop('ports',None)
    ports=parse_ports(data.get('ports'))
    if ports and protocol not in ('tcp','udp'):
        raise HTTPException(422,'ports hanya valid untuk protocol tcp atau udp')
    if ports is not None:
        data['ports']=ports
    else:
        data.pop('ports',None)

    source_type=data.get('source_type','cidr')
    if source_type not in POLICY_SOURCE_TYPES:
        raise HTTPException(422,'source_type harus cidr, site, user, atau group')
    data['source_type']=source_type
    if source_type=='cidr':
        try:data['source_cidr']=cidr(data['source_cidr'])
        except (KeyError,ValueError,TypeError):raise HTTPException(422,'Invalid fields; credentials must be 8-128 safe printable characters')
        data.pop('source_ref',None)
    else:
        kind_map={'site':'sites','user':'users','group':'groups'}
        ref=data.get('source_ref')
        if type(ref) is not int or not any(r['id']==ref for r in rows(kind_map[source_type])):
            raise HTTPException(422,f'source_ref {source_type} tidak ditemukan')
        data['source_ref']=ref
        data.pop('source_cidr',None)

    dest_type=data.get('destination_type','cidr')
    if dest_type not in POLICY_DEST_TYPES:
        raise HTTPException(422,'destination_type harus cidr, site, atau vpc')
    data['destination_type']=dest_type
    if dest_type=='cidr':
        try:data['destination_cidr']=cidr(data['destination_cidr'])
        except (KeyError,ValueError,TypeError):raise HTTPException(422,'Invalid fields; credentials must be 8-128 safe printable characters')
        data.pop('destination_ref',None)
    elif dest_type=='site':
        ref=data.get('destination_ref')
        if type(ref) is not int or not any(r['id']==ref for r in rows('sites')):
            raise HTTPException(422,'destination_ref site tidak ditemukan')
        data['destination_ref']=ref
        data.pop('destination_cidr',None)
    else:
        data.pop('destination_ref',None)
        data.pop('destination_cidr',None)

    if 'description' in data:
        if not isinstance(data['description'],str) or not DESC_RE.fullmatch(data['description']):
            raise HTTPException(422,'description tidak valid')

    if any(x['name']==data['name'] and x['id']!=old.get('id') for x in rows('policies')):
        raise HTTPException(409,'Name already exists')
    return data


def sync_site_peers(site_id, peer_ids):
    """Maintain symmetric peer_sites across all sites rows within an active transaction.
    Returns list of peer site IDs whose peer_sites were modified.
    """
    wanted = set(peer_ids)
    changed_ids = []
    for other in rows('sites'):
        oid = other['id']
        if oid == site_id:
            continue
        cur_peers = list(other.get('peer_sites', []))
        changed = False
        if oid in wanted and site_id not in cur_peers:
            cur_peers.append(site_id)
            changed = True
        elif oid not in wanted and site_id in cur_peers:
            cur_peers = [x for x in cur_peers if x != site_id]
            changed = True
        if changed:
            body = {k: v for k, v in other.items() if k != 'id'}
            body['peer_sites'] = cur_peers
            db.execute('UPDATE objects SET body=? WHERE id=?', (json.dumps(body), oid))
            changed_ids.append(oid)
    return changed_ids


def detach_site_peers(site_id):
    """Remove deleted site_id from any other site's peer_sites list."""
    return sync_site_peers(site_id, [])


def validate(kind,body,old=None):
    old=old or {}
    if not isinstance(body,dict):raise HTTPException(422,'Invalid request')
    if kind=='sites':return validate_site(body,old)
    if kind=='groups':return validate_group(body,old)
    if kind=='routes':return validate_route(body,old)
    if kind=='policies':return validate_policy(body,old)
    if kind=='connections':
        if topology_of(body,old)=='hub':return validate_hub(body,old)
        body={k:v for k,v in body.items() if k!='topology'}
    fields={'connections':{'name','remote_address','remote_id','local_ts','remote_ts','psk','enabled'},'users':USER_FIELDS}[kind]
    if set(body)-fields:raise HTTPException(422,'Unknown fields')
    if kind=='users' and 'traffic_mode' in body and body['traffic_mode'] not in TRAFFIC_MODES:
        raise HTTPException(422,'traffic_mode must be split or full')
    if kind=='users' and 'auth_method' in body and body['auth_method'] not in AUTH_METHODS_USER:
        raise HTTPException(422,'auth_method must be eap-mschapv2, pubkey, or eap-tls')
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
            taken_ids={(r.get(side) or {}).get('id') for r in rows('connections') if r['id']!=old.get('id') for side in SITES}
            taken_ids.update(r.get('ike_id') for r in rows('sites') if r.get('ike_id'))
            if data['remote_id'] in taken_ids:raise HTTPException(422,'remote_id sudah dipakai sebagai ID site VPN Hub')
            data['local_ts']=','.join(local);data['remote_ts']=','.join(remote);data['psk']=credential(data['psk'])
        elif kind=='users':
            data['username']=safe(data['username'])
            data.setdefault('auth_method','eap-mschapv2')
            if data['auth_method']=='eap-mschapv2':
                data.pop('cert_id',None)
                if not data.get('password'):
                    raise HTTPException(422,'Password wajib diisi untuk metode eap-mschapv2')
                data['password']=credential(data['password'])
            else:
                if data.get('password'):data['password']=credential(data['password'])
                if 'cert_id' not in data or data['cert_id'] is None:
                    raise HTTPException(422,'cert_id wajib untuk autentikasi sertifikat (pubkey/eap-tls)')
                data['cert_id']=_check_cert(data['cert_id'],'user')
            data['groups']=_check_id_list(data.get('groups',[]),'groups','groups')
            data['allowed_sites']=_check_id_list(data.get('allowed_sites',[]),'sites','allowed_sites')
            if 'allowed_cidrs' not in data:
                if data['groups'] or data['allowed_sites']:
                    data['allowed_cidrs']=[]
                else:
                    data['allowed_cidrs']=default_lan_cidrs()
            if not isinstance(data['allowed_cidrs'],list):raise ValueError()
            data['allowed_cidrs']=[cidr(x) for x in data['allowed_cidrs']]
            if len(data['allowed_cidrs'])>16:raise ValueError()
            if not data['allowed_cidrs'] and not (data['groups'] or data['allowed_sites']):
                raise HTTPException(422,'Minimal satu tujuan akses wajib diisi: allowed_cidrs, allowed_sites, atau groups')
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
    except HTTPException:raise
    except (KeyError,ValueError,TypeError):raise HTTPException(422,'Invalid fields; credentials must be 8-128 safe printable characters')
    if kind=='connections':
        check_selectors(local,remote)
        if not old.get('id'):data['topology']='direct'
    unique='username' if kind=='users' else 'name'
    if any(x[unique]==data[unique] and x['id']!=old.get('id') for x in rows(kind)):raise HTTPException(409,'Name already exists')
    return data
