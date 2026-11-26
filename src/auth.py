"""Token-based authentication and scoped RBAC for Customer Portal (CP) and CLI/UI.

Supports:
- `X-API-Key: <token>` (100% backward compatible with existing UI & scripts)
- `Authorization: Bearer <token>` (standard Token-based auth for Customer Portal)

The bootstrap key in `VPNAAS_API_KEY` always has role `admin`.
Additional scoped tokens (`admin`, `operator`, `readonly`) are persisted in SQLite
as SHA-256 hashes only; plaintext is returned once at creation.
"""
import datetime
import hashlib
import os
import re
import secrets
from fastapi import Header, HTTPException

ROLES = ('readonly', 'operator', 'admin')
_ROLE_RANK = {'readonly': 1, 'operator': 2, 'admin': 3}
_TOKEN_NAME = re.compile(r'[A-Za-z0-9 _.@:-]{1,64}')


def init_tokens_table(conn):
    conn.execute('''CREATE TABLE IF NOT EXISTS tokens (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT UNIQUE NOT NULL,
        token_hash TEXT UNIQUE NOT NULL,
        prefix TEXT NOT NULL,
        role TEXT NOT NULL,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
        expires_at TEXT,
        revoked INTEGER DEFAULT 0,
        last_used_at TEXT
    )''')
    conn.commit()


def _hash(token: str) -> str:
    return hashlib.sha256(token.encode('utf-8')).hexdigest()


def _now_utc() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


def _extract_token(x_api_key: str, authorization: str) -> str:
    if x_api_key:
        return x_api_key.strip()
    if authorization:
        parts = authorization.strip().split(None, 1)
        if len(parts) == 2 and parts[0].lower() == 'bearer' and parts[1].strip():
            return parts[1].strip()
    return ''


def authenticate(token: str):
    if not token:
        raise HTTPException(401, 'Unauthorized')
    root_key = os.environ.get('VPNAAS_API_KEY', '')
    if root_key and secrets.compare_digest(token, root_key):
        return {'role': 'admin', 'token_id': None, 'name': 'root-api-key'}

    from store import db, lock
    digest = _hash(token)
    with lock:
        row = db.execute(
            'SELECT id, name, role, expires_at, revoked FROM tokens WHERE token_hash = ?',
            (digest,),
        ).fetchone()
        if not row:
            raise HTTPException(401, 'Unauthorized')
        token_id, name, role, expires_at, revoked = row
        if revoked:
            raise HTTPException(401, 'Token revoked')
        if expires_at:
            try:
                exp = datetime.datetime.fromisoformat(expires_at.replace('Z', '+00:00'))
                if exp.tzinfo is None:
                    exp = exp.replace(tzinfo=datetime.timezone.utc)
                if _now_utc() >= exp:
                    raise HTTPException(401, 'Token expired')
            except HTTPException:
                raise
            except ValueError:
                raise HTTPException(401, 'Unauthorized')
        if role not in _ROLE_RANK:
            raise HTTPException(401, 'Unauthorized')
        db.execute(
            'UPDATE tokens SET last_used_at = CURRENT_TIMESTAMP WHERE id = ?',
            (token_id,),
        )
        db.commit()
        return {'role': role, 'token_id': token_id, 'name': name}


def require_role(min_role: str):
    min_rank = _ROLE_RANK[min_role]

    def _dep(
        x_api_key: str = Header(default=''),
        authorization: str = Header(default=''),
    ):
        principal = authenticate(_extract_token(x_api_key, authorization))
        if _ROLE_RANK[principal['role']] < min_rank:
            raise HTTPException(403, f'Insufficient token role; requires {min_role}')
        return principal

    return _dep


authorize = require_role('readonly')
require_readonly = require_role('readonly')
require_operator = require_role('operator')
require_admin = require_role('admin')


def list_tokens():
    from store import db, lock
    with lock:
        cur = db.execute(
            'SELECT id, name, prefix, role, created_at, expires_at, revoked, last_used_at '
            'FROM tokens ORDER BY id'
        )
        return [
            {
                'id': r[0],
                'name': r[1],
                'prefix': r[2],
                'role': r[3],
                'created_at': r[4],
                'expires_at': r[5],
                'revoked': bool(r[6]),
                'last_used_at': r[7],
            }
            for r in cur.fetchall()
        ]


def create_token(body: dict):
    if not isinstance(body, dict):
        raise HTTPException(422, 'Invalid request')
    allowed = {'name', 'role', 'expires_days'}
    if set(body) - allowed:
        raise HTTPException(422, 'Unknown fields')
    name = body.get('name')
    if not isinstance(name, str) or not _TOKEN_NAME.fullmatch(name):
        raise HTTPException(422, 'Invalid token name')
    role = body.get('role', 'operator')
    if role not in ROLES:
        raise HTTPException(422, 'role must be readonly, operator, or admin')
    expires_days = body.get('expires_days')
    expires_at = None
    if expires_days is not None:
        if type(expires_days) is not int or not 1 <= expires_days <= 3650:
            raise HTTPException(422, 'expires_days must be an integer 1..3650')
        expires_at = (_now_utc() + datetime.timedelta(days=expires_days)).strftime('%Y-%m-%dT%H:%M:%SZ')

    plaintext = 'vpnaas_' + secrets.token_urlsafe(32)
    prefix = plaintext[:14]
    digest = _hash(plaintext)

    from store import db, lock, audit
    import sqlite3
    with lock:
        try:
            cur = db.execute(
                'INSERT INTO tokens(name, token_hash, prefix, role, expires_at) VALUES(?,?,?,?,?)',
                (name, digest, prefix, role, expires_at),
            )
            ident = cur.lastrowid
            audit('create', 'tokens', ident)
            db.commit()
        except sqlite3.IntegrityError:
            db.rollback()
            raise HTTPException(409, 'Token name already exists')
        row = db.execute(
            'SELECT id, name, prefix, role, created_at, expires_at, revoked, last_used_at '
            'FROM tokens WHERE id = ?',
            (ident,),
        ).fetchone()
    return {
        'id': row[0],
        'name': row[1],
        'prefix': row[2],
        'role': row[3],
        'created_at': row[4],
        'expires_at': row[5],
        'revoked': bool(row[6]),
        'last_used_at': row[7],
        'token': plaintext,
    }


def revoke_token(ident: int):
    from store import db, lock, audit
    with lock:
        row = db.execute('SELECT id FROM tokens WHERE id = ?', (ident,)).fetchone()
        if not row:
            raise HTTPException(404, 'Not found')
        db.execute('UPDATE tokens SET revoked = 1 WHERE id = ?', (ident,))
        audit('revoke', 'tokens', ident)
        db.commit()
    return {'revoked': True, 'id': ident}
