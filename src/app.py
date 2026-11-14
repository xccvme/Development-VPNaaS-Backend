import os
import secrets
from contextlib import asynccontextmanager
from fastapi import FastAPI, Header, HTTPException, Depends

@asynccontextmanager
async def lifespan(_app):
    import sessions
    sessions.start()
    try:
        yield
    finally:
        await sessions.stop()

app=FastAPI(title='VPNaaS PoC',lifespan=lifespan)
def authorize(x_api_key: str=Header(default='')):
    if not secrets.compare_digest(x_api_key, os.environ.get('VPNAAS_API_KEY','')) or not x_api_key:
        raise HTTPException(401,'Unauthorized')
@app.get('/api/health',dependencies=[Depends(authorize)])
def health():
    return {'status':'ok'}

from store import db,lock,rows,get,public,validate,audit
import json

def apply_configuration():
    if os.environ.get('VPNAAS_DRY_RUN')!='1':
        from vpn import apply
        apply()

def register(kind):
    def listing():
        with lock:result = [public(r) for r in rows(kind)]
        if kind == 'connections':return with_hub_runtime(result)
        if kind == 'users':
            from runtime import user_runtime
            runtime = user_runtime(result)
            result = [dict(user, **runtime[user['id']]) for user in result]
        return result
    def create(body: dict):
        with lock:
            data=validate(kind,body)
            try:
                cur=db.execute('INSERT INTO objects(kind,body) VALUES(?,?)',(kind,json.dumps(data)))
                ident=cur.lastrowid
                apply_configuration();audit('create',kind,ident);db.commit()
                return decorate(kind,public(dict(data,id=ident)))
            except Exception:
                db.rollback();raise
    def update(ident:int,body:dict):
        with lock:
            previous=get(kind,ident)
            data=validate(kind,body,previous)
            try:
                db.execute('UPDATE objects SET body=? WHERE id=?',(json.dumps(data),ident))
                from vpn import revoke
                revoke(kind,ident,**({"row":previous} if kind=="connections" else {}))
                apply_configuration();audit('update',kind,ident);db.commit()
                return decorate(kind,public(dict(data,id=ident)))
            except Exception:
                db.rollback();raise
    def delete(ident:int):
        with lock:
            previous=get(kind,ident)
            try:
                db.execute('DELETE FROM objects WHERE id=?',(ident,))
                from vpn import revoke
                revoke(kind,ident,**({"row":previous} if kind=="connections" else {}))
                apply_configuration();audit('delete',kind,ident);db.commit()
                return {'deleted':True}
            except Exception:
                db.rollback();raise
    deps=[Depends(authorize)]
    app.add_api_route('/api/'+kind,listing,methods=['GET'],dependencies=deps)
    if kind=='users':
        def detail(ident:int):
            with lock:user=public(get(kind,ident))
            from runtime import user_runtime
            return dict(user,**user_runtime([user])[user['id']])
        app.add_api_route('/api/'+kind+'/{ident}',detail,methods=['GET'],dependencies=deps)
    if kind=='connections':
        def connection_detail(ident:int):
            with lock:row=public(get(kind,ident))
            return with_hub_runtime([row])[0]
        app.add_api_route('/api/'+kind+'/{ident}',connection_detail,methods=['GET'],dependencies=deps)
    app.add_api_route('/api/'+kind,create,methods=['POST'],dependencies=deps)
    app.add_api_route('/api/'+kind+'/{ident}',update,methods=['PUT'],dependencies=deps)
    app.add_api_route('/api/'+kind+'/{ident}',delete,methods=['DELETE'],dependencies=deps)
def with_hub_runtime(result):
    hubs=[r for r in result if r.get('topology')=='hub']
    if not hubs:return result
    from runtime import hub_runtime
    runtime=hub_runtime(hubs)
    for r in hubs:
        for side in ('site_a','site_b'):r[side]=dict(r[side],**runtime[r['id']][side])
    return result
def decorate(kind,row):
    return with_hub_runtime([row])[0] if kind=='connections' else row
register('connections')
register('users')
register('policies')

from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
@app.exception_handler(RequestValidationError)
async def sanitized_validation(request,exc):
    return JSONResponse({'detail':'Invalid request'},status_code=422)
from pathlib import Path
@app.get('/api/audit',dependencies=[Depends(authorize)])
def audit_list():
    with lock:
        return [dict(zip(['id','timestamp','action','resource','resource_id'],r)) for r in db.execute('SELECT * FROM audit ORDER BY id DESC LIMIT 500')]
@app.get('/api/status',dependencies=[Depends(authorize)])
def vpn_status():
    if os.environ.get('VPNAAS_DRY_RUN')=='1':return {'raw':'test mode (not daemon status)','connections':''}
    from vpn import status
    try:
        result=status()
        if os.environ.get('VPNAAS_ROUTE_AUTO')=='1':
            from network import diagnostics
            result['network']=diagnostics(rows('users'))
        return result
    except Exception:raise HTTPException(503,'strongSwan status unavailable')
@app.get('/api/overview',dependencies=[Depends(authorize)])
def overview():
    with lock:
        result={k:len(rows(k)) for k in ['connections','users','policies']}
        result['enabled_connections']=sum(r['enabled'] for r in rows('connections'))
    result['vpn']=vpn_status()
    return result
@app.get('/api/users/{ident}/profile',dependencies=[Depends(authorize)])
def profile(ident:int):
    with lock:u=get('users',ident)
    ca=Path('/etc/swanctl/x509ca/ca.pem')
    from vpn import vip,full_dns
    mode=u.get('traffic_mode','split')
    data=dict(username=u['username'],password=u['password'],traffic_mode=mode,server=os.environ.get('VPNAAS_PUBLIC_IP','203.0.113.10'),server_id=os.environ.get('VPNAAS_PUBLIC_IP','203.0.113.10'),virtual_ip=vip(u),allowed_cidrs=u['allowed_cidrs'],ca_certificate=ca.read_text() if ca.exists() else '')
    if mode=='full':data['dns']=full_dns()
    return JSONResponse(data,headers={'Cache-Control':'no-store','Content-Disposition':f'attachment; filename="user-{ident}.json"'})
@app.post('/api/connections/{ident}/initiate',dependencies=[Depends(authorize)])
def initiate(ident:int):
    from vpn import action
    with lock:return action(get('connections',ident),'initiate')
@app.post('/api/connections/{ident}/terminate',dependencies=[Depends(authorize)])
def terminate(ident:int):
    from vpn import action
    with lock:return action(get('connections',ident),'terminate')



from typing import Literal
from fastapi.responses import PlainTextResponse
@app.get('/api/connections/{ident}/sites/{side}/config',dependencies=[Depends(authorize)])
def site_config(ident:int,side:Literal['a','b'],format:Literal['swanctl','script']='swanctl'):
    from vpn import is_hub
    import spoke
    with lock:c=get('connections',ident)
    if not is_hub(c):raise HTTPException(409,'Bukan koneksi VPN Hub')
    if format=='script':text,filename=spoke.script(c,side),spoke.filename(c,side,'script')
    else:text,filename=spoke.swanctl(c,side),spoke.filename(c,side,'swanctl')
    return PlainTextResponse(text,headers={'Cache-Control':'no-store','Content-Disposition':f'attachment; filename="{filename}"'})
@app.post('/api/connections/{ident}/sites/{side}/connect',dependencies=[Depends(authorize)])
def site_connect(ident:int,side:Literal['a','b']):
    from vpn import site_action
    with lock:c=get('connections',ident)
    return site_action(c,side,'connect')
@app.post('/api/connections/{ident}/sites/{side}/disconnect',dependencies=[Depends(authorize)])
def site_disconnect(ident:int,side:Literal['a','b']):
    from vpn import site_action
    with lock:c=get('connections',ident)
    return site_action(c,side,'disconnect')
