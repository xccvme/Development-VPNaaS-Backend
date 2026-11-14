"""Per-account concurrent session limit enforcement (strongSwan has no native per-EAP-user cap).

Every interval the enforcer takes one complete `swanctl --list-sas --raw` snapshot,
groups ESTABLISHED IKE SAs by authenticated EAP identity and, when an account has
more sessions than its max_sessions, terminates the newest surplus SAs by their
numeric IKE unique id (`--ike-id`), never by connection name, so the oldest
max_sessions sessions are left untouched. SAs from the same remote host:port are
one session (make-before-break reauthentication overlap, not a second device).
Dry-run, daemon errors and malformed snapshots never terminate anything.
"""
import asyncio
import logging
import os
import sys

log = logging.getLogger('vpnaas.sessions')
if not log.handlers:
    handler = logging.StreamHandler(sys.stderr)  # systemd unit -> journald
    handler.setFormatter(logging.Formatter('vpnaas-sessions %(levelname)s %(message)s'))
    log.addHandler(handler)
    log.setLevel(logging.INFO)
    log.propagate = False

INTERVAL = float(os.environ.get('VPNAAS_SESSION_LIMIT_INTERVAL', '5'))
TASK = None


def _age(sa):
    try:
        return int(sa.get('established', 0))
    except (TypeError, ValueError):
        return 0


def _uid(sa):
    try:
        return int(sa.get('uniqueid'))
    except (TypeError, ValueError):
        return None


def plan(users, sas):
    """Return [(user, ike_id)] to terminate: newest surplus beyond max_sessions."""
    result = []
    for user in users:
        limit = user.get('max_sessions', 3)
        mine = []
        for sa in sas:
            if sa.get('state') != 'ESTABLISHED' or _uid(sa) is None:
                continue
            identity = sa.get('remote-eap-id') or sa.get('remote-xauth-id')
            if (identity != user['username']) if identity else (sa.get('name') != 'user-' + str(user['id'])):
                continue
            mine.append(sa)
        endpoints = {}
        for sa in mine:
            endpoints.setdefault((sa.get('remote-host'), sa.get('remote-port')), []).append(sa)
        if len(endpoints) <= limit:
            continue
        # Oldest first: longest established, then lowest (earliest) unique id.
        ordered = sorted(endpoints.values(),
                         key=lambda group: (-max(_age(s) for s in group), min(_uid(s) for s in group)))
        for group in ordered[limit:]:
            for sa in sorted(group, key=_uid):
                result.append((user, str(_uid(sa))))
    return result


def enforce_once():
    if os.environ.get('VPNAAS_DRY_RUN') == '1':
        return []
    import vpn
    from runtime import parse_sas
    from store import lock, rows, audit, db
    sas = parse_sas(vpn.run(['swanctl', '--list-sas', '--raw'], timeout=8))
    with lock:
        users = [u for u in rows('users') if u.get('enabled', True)]
    actions = []
    for user, ike_id in plan(users, sas):
        ok = True
        try:
            # Numeric unique id selects exactly one IKE_SA (and its CHILD_SAs).
            vpn.run(['swanctl', '--terminate', '--ike-id', ike_id, '--force'], timeout=10)
        except Exception:
            ok = False
        log.warning('session limit: user id=%s username=%s max_sessions=%s terminated IKE_SA #%s ok=%s',
                    user['id'], user['username'], user.get('max_sessions', 3), ike_id, ok)
        if ok:
            with lock:
                try:
                    audit('session_limit', 'users', user['id']); db.commit()
                except Exception:
                    db.rollback()
        actions.append({'user_id': user['id'], 'username': user['username'], 'ike_id': ike_id, 'ok': ok})
    return actions


async def session_limit_loop(interval=None):
    interval = INTERVAL if interval is None else interval
    log.info('session limit enforcer started, interval %ss', interval)
    while True:
        try:
            await asyncio.to_thread(enforce_once)
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # non-fatal: never take the API down
            log.error('session limit check skipped: %s', type(exc).__name__)
        await asyncio.sleep(interval)


def start():
    global TASK
    if os.environ.get('VPNAAS_DRY_RUN') == '1' or os.environ.get('VPNAAS_SESSION_LIMIT') == '0':
        TASK = None
        return None
    TASK = asyncio.create_task(session_limit_loop())
    return TASK


async def stop():
    global TASK
    task, TASK = TASK, None
    if task:
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass
