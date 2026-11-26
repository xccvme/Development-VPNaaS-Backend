"""VICI native integration helper with safe swanctl CLI fallback.

Uses strongSwan's native VICI socket (`vici.Session()`) whenever available to
avoid subprocess fork/exec overhead on 1 vCPU / 1 GB RAM gateway VMs, while
falling back cleanly to `vpn.run(['swanctl', ...])` when VICI is unavailable or
when tests monkeypatch `vpn.run`.
"""
import os


def _decode(obj):
    if isinstance(obj, bytes):
        return obj.decode('utf-8', errors='replace')
    if isinstance(obj, dict):
        return {_decode(k): _decode(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_decode(x) for x in obj]
    return obj


def _use_vici():
    if os.environ.get('VPNAAS_DRY_RUN') == '1':
        return False
    if os.environ.get('VPNAAS_USE_VICI', '0') != '1':
        return False
    try:
        import vici  # noqa: F401
        return True
    except ImportError:
        return False


def session():
    import vici
    return vici.Session()


def list_sas_native():
    """Return normalized list of IKE SA dicts (matching runtime.parse_sas schema)."""
    s = session()
    out = []
    for item in s.list_sas():
        decoded = _decode(item)
        for name, sa in decoded.items():
            if isinstance(sa, dict):
                out.append(dict(sa, name=name))
    return out


def list_sas():
    """Read live IKE SAs: uses native VICI when VPNAAS_USE_VICI=1, else swanctl --raw."""
    if _use_vici():
        try:
            return list_sas_native()
        except Exception:
            pass
    import vpn
    from runtime import parse_sas
    return parse_sas(vpn.run(['swanctl', '--list-sas', '--raw'], timeout=8))


def list_conns():
    if _use_vici():
        try:
            return _decode(session().get_conns()).get('conns', [])
        except Exception:
            pass
    return None


def terminate_ike(name=None, ike_id=None, timeout=10, force=False):
    """Terminate an IKE SA by name or numeric uniqueid."""
    if _use_vici():
        try:
            req = {'timeout': str(int(timeout) * 1000)}
            if ike_id is not None:
                req['ike-id'] = str(ike_id)
            elif name is not None:
                req['ike'] = str(name)
            if force:
                req['force'] = 'yes'
            logs = []
            for event in session().terminate(req):
                decoded = _decode(event)
                if decoded.get('msg'):
                    logs.append(decoded['msg'])
            return '\n'.join(logs) or 'terminated'
        except (ImportError, OSError):
            pass
    import vpn
    args = ['swanctl', '--terminate']
    if ike_id is not None:
        args += ['--ike-id', str(ike_id)]
    elif name is not None:
        args += ['--ike', str(name)]
    if force:
        args.append('--force')
    else:
        args += ['--timeout', str(timeout)]
    return vpn.run(args, timeout=max(10, int(timeout) + 6))


def initiate_child(child, timeout=12):
    if _use_vici():
        try:
            logs = []
            for event in session().initiate({'child': str(child), 'timeout': str(int(timeout) * 1000)}):
                decoded = _decode(event)
                if decoded.get('msg'):
                    logs.append(decoded['msg'])
            return '\n'.join(logs) or 'initiated'
        except (ImportError, OSError):
            pass
    import vpn
    return vpn.run(['swanctl', '--initiate', '--child', str(child), '--timeout', str(timeout)], timeout=max(18, int(timeout) + 6))


def ping_daemon():
    """Check whether charon daemon responds over VICI or swanctl."""
    if os.environ.get('VPNAAS_DRY_RUN') == '1':
        return True, 'dry-run'
    try:
        import vici
        ver = _decode(vici.Session().version())
        return True, f"strongSwan {ver.get('version', 'unknown')} (VICI)"
    except Exception:
        pass
    try:
        import vpn
        vpn.run(['swanctl', '--version'], timeout=5)
        return True, 'strongSwan (swanctl)'
    except Exception as exc:
        return False, str(exc)
