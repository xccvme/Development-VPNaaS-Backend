"""First-boot & golden-image (snapshot) provisioning for VPNaaS Gateway VMs.

Handles three lifecycle scenarios automatically before strongSwan & vpnaas-api start:
1. Sealed Golden Image (`vpnaas-prepare-image` / `install.sh --prepare-image`):
   Generates fresh per-VM API key, Root CA, Server Cert (SAN = new public IP),
   conflict-free C2S VIP pool, `/etc/vpnaas/backend.env`, and public routing.
2. Direct Snapshot Clone (operator snapshotted a live VM without sealing):
   Detects changed cloud-init `instance-id` or SMBIOS/DMI `product_uuid` against
   `/var/lib/vpnaas/instance-identity.json`, wipes inherited builder state/secrets,
   and provisions fresh unique credentials, PKI, pool, and network config.
3. Normal Reboot of Existing VM (same identity):
   Preserves SQLite DB, Root CA, issued certs, VIP pool, and API key. Updates
   `/etc/vpnaas/backend.env` if NICs/IPs/VPC changed (unless `VPNAAS_PIN_NETWORK=1`),
   rotates ONLY `server.pem` under the existing CA if the public IP changed, and
   re-applies multi-NIC public routing guard (`network.ensure_public_routing`).
"""
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.request

DEFAULT_ENV_PATH = Path('/etc/vpnaas/backend.env')
DEFAULT_KEY_PATH = Path('/etc/vpnaas/api.key')
DEFAULT_BOOTSTRAP_ENV = Path('/etc/vpnaas/bootstrap.env')
DEFAULT_STATE_DIR = Path('/var/lib/vpnaas')
DEFAULT_IDENTITY_PATH = DEFAULT_STATE_DIR / 'instance-identity.json'
DEFAULT_GOLDEN_MARKER = DEFAULT_STATE_DIR / '.golden-image'
DEFAULT_BACKUP_DIR = Path('/var/backups/vpnaas')
DEFAULT_FIREWALL_NFT = Path('/opt/vpnaas/firewall.nft')
LAN_PLACEHOLDER = '192.0.2.0/24'

VIRTUAL_DEV = re.compile(r'^(docker|br-|veth|virbr|lo$|cni|flannel|cali|vpnaas)')
META_VAL_RE = re.compile(r'^[A-Za-z0-9_.-]{1,64}$')
IFNAME_RE = re.compile(r'^[A-Za-z0-9_.:-]{1,15}$')
_INVALID_UUIDS = {'', '00000000-0000-0000-0000-000000000000', 'ffffffff-ffff-ffff-ffff-ffffffffffff', 'none', 'unknown'}


def _log(msg: str):
    print(f'vpnaas-bootstrap: {msg}', flush=True)


def _read_text(path: Path) -> str:
    try:
        return path.read_text(encoding='utf-8').strip()
    except OSError:
        return ''


def _atomic_write(path: Path, text: str, mode: int = 0o600):
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent)
    try:
        try:
            os.fchmod(fd, mode)
        except (AttributeError, OSError):
            pass
        with os.fdopen(fd, 'w', encoding='utf-8', newline='\n') as f:
            f.write(text)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def _parse_env_file(path: Path) -> dict:
    if not path.exists():
        return {}
    out = {}
    for line in path.read_text(encoding='utf-8').splitlines():
        line = line.strip()
        if not line or line.startswith('#') or '=' not in line:
            continue
        k, v = line.split('=', 1)
        out[k.strip()] = v.strip().strip('"').strip("'")
    return out


def read_vm_identity(
    dmi_path: Path = Path('/sys/class/dmi/id/product_uuid'),
    cloud_id_path: Path = Path('/var/lib/cloud/data/instance-id'),
    machine_id_path: Path = Path('/etc/machine-id'),
) -> dict:
    dmi = _read_text(dmi_path).lower()
    if dmi in _INVALID_UUIDS:
        dmi = ''
    cloud_id = _read_text(cloud_id_path)
    if cloud_id.lower() in ('', 'iid-datasource-none', 'nocloud', 'none'):
        cloud_id = ''
    mid = _read_text(machine_id_path).lower()
    if mid in _INVALID_UUIDS:
        mid = ''
    return {
        'dmi_uuid': dmi,
        'cloud_instance_id': cloud_id,
        'machine_id': mid,
    }


def is_clone_or_first_boot(
    prev_identity: dict,
    curr_identity: dict,
    marker_exists: bool,
    env_exists: bool,
    pki_complete: bool,
) -> tuple:
    """Distinguish a freshly booted golden-image clone from a normal reboot."""
    if marker_exists:
        return True, 'golden-image-marker'
    if prev_identity:
        prev_cid = (prev_identity.get('cloud_instance_id') or '').strip()
        curr_cid = (curr_identity.get('cloud_instance_id') or '').strip()
        if prev_cid and curr_cid and prev_cid != curr_cid:
            return True, 'cloud-instance-id-changed'
        prev_dmi = (prev_identity.get('dmi_uuid') or '').strip().lower()
        curr_dmi = (curr_identity.get('dmi_uuid') or '').strip().lower()
        if prev_dmi and curr_dmi and prev_dmi != curr_dmi:
            return True, 'dmi-uuid-changed'
        if not prev_cid and not prev_dmi:
            prev_mid = (prev_identity.get('machine_id') or '').strip().lower()
            curr_mid = (curr_identity.get('machine_id') or '').strip().lower()
            if prev_mid and curr_mid and prev_mid != curr_mid:
                return True, 'machine-id-changed'
    if not env_exists and not pki_complete:
        return True, 'uninitialized-host'
    return False, 'same-instance'


def _is_global_ipv4(val: str) -> bool:
    if not val:
        return False
    try:
        ip = ipaddress.IPv4Address(val)
        return ip.is_global and not ip.is_private
    except ValueError:
        return False


def _is_private_ipv4(val: str) -> bool:
    if not val:
        return False
    try:
        ip = ipaddress.IPv4Address(val)
        return ip.is_private and not ip.is_loopback and not ip.is_link_local
    except ValueError:
        return False


def fetch_metadata_public_ip(timeout: float = 2.0) -> str:
    """Query OpenStack/EC2 link-local metadata service for Floating IP / public IPv4."""
    urls = (
        'http://169.254.169.254/latest/meta-data/public-ipv4',
        'http://169.254.169.254/2009-04-04/meta-data/public-ipv4',
    )
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    for url in urls:
        try:
            with opener.open(url, timeout=timeout) as resp:
                if resp.status == 200:
                    val = resp.read(64).decode('ascii', errors='ignore').strip()
                    if _is_global_ipv4(val):
                        return str(ipaddress.IPv4Address(val))
        except Exception:
            continue
    return ''


def _kernel_routes_and_addrs():
    routes = json.loads(subprocess.check_output(['ip', '-j', '-4', 'route', 'show', 'table', 'main'], timeout=5))
    addrs = json.loads(subprocess.check_output(['ip', '-j', '-4', 'addr'], timeout=5))
    return routes, addrs


def detect_network(
    main_routes: list,
    addresses: list,
    overrides: dict = None,
    metadata_ip_fn=None,
) -> dict:
    """Detect PUBLIC_IP, PUBLIC_IF, BIND_IP, LAN_CIDR, LAN_IF, LAN_IP cleanly on 1-NIC, 2-NIC, or Floating-IP VMs."""
    overrides = overrides or {}
    default_routes = [
        r for r in main_routes
        if r.get('dst') == 'default' and r.get('dev') and not VIRTUAL_DEV.match(r.get('dev', ''))
    ]
    default_devs = {r['dev'] for r in default_routes}

    global_nics = []
    private_nics = []
    all_nics = []
    for iface in addresses:
        ifname = iface.get('ifname', '')
        if not ifname or VIRTUAL_DEV.match(ifname) or not IFNAME_RE.fullmatch(ifname):
            continue
        for info in iface.get('addr_info', []):
            if info.get('family') != 'inet' or info.get('scope') != 'global':
                continue
            local_ip = info.get('local', '')
            prefixlen = info.get('prefixlen')
            if not local_ip or prefixlen is None:
                continue
            item = (ifname, local_ip, int(prefixlen))
            all_nics.append(item)
            if _is_global_ipv4(local_ip):
                global_nics.append(item)
            elif _is_private_ipv4(local_ip):
                private_nics.append(item)

    # 1. Pick public interface & local bind IP (global IPv4 NIC wins even if private NIC has lower metric!)
    pub_choice = next((x for x in global_nics if x[0] in default_devs), None)
    if not pub_choice and global_nics:
        pub_choice = global_nics[0]
    if not pub_choice and default_routes:
        best_def = min(default_routes, key=lambda r: int(r.get('metric', 0)))
        dev = best_def['dev']
        pub_choice = next((x for x in all_nics if x[0] == dev), None)
    if not pub_choice and all_nics:
        pub_choice = all_nics[0]

    if not pub_choice:
        raise RuntimeError('No active IPv4 network interface detected')

    detected_pub_if, detected_bind_ip, _ = pub_choice
    detected_pub_ip = detected_bind_ip

    # Floating IP / 1:1 NAT detection when local public NIC only holds RFC1918 IP
    explicit_pub_ip = (overrides.get('PUBLIC_IP') or overrides.get('VPNAAS_PUBLIC_IP') or '').strip()
    if explicit_pub_ip:
        detected_pub_ip = str(ipaddress.IPv4Address(explicit_pub_ip))
    elif not _is_global_ipv4(detected_pub_ip) and metadata_ip_fn is not None:
        meta_ip = metadata_ip_fn()
        if meta_ip and _is_global_ipv4(meta_ip):
            detected_pub_ip = meta_ip

    pub_if = (overrides.get('PUBLIC_IF') or overrides.get('VPNAAS_PUBLIC_IF') or detected_pub_if).strip()
    if not IFNAME_RE.fullmatch(pub_if):
        pub_if = detected_pub_if

    # Resolve bind_ip on the chosen pub_if
    bind_ip = (overrides.get('BIND_IP') or overrides.get('VPNAAS_BIND_IP') or '').strip()
    if not bind_ip:
        nic_ips = [x[1] for x in all_nics if x[0] == pub_if]
        if detected_pub_ip in nic_ips:
            bind_ip = detected_pub_ip
        elif nic_ips:
            bind_ip = nic_ips[0]
        else:
            bind_ip = detected_bind_ip

    # 2. Pick private VPC / LAN interface (any non-public, non-virtual NIC holding private IPv4)
    lan_choice = next((x for x in private_nics if x[0] != pub_if), None)
    if lan_choice:
        det_lan_if, det_lan_ip, det_lan_pfx = lan_choice
        det_lan_cidr = str(ipaddress.IPv4Network(f'{det_lan_ip}/{det_lan_pfx}', strict=False))
    else:
        det_lan_if = pub_if
        det_lan_ip = bind_ip
        det_lan_cidr = LAN_PLACEHOLDER

    lan_if = (overrides.get('LAN_IF') or overrides.get('VPNAAS_LAN_IF') or det_lan_if).strip()
    lan_ip = (overrides.get('LAN_IP') or overrides.get('VPNAAS_LAN_IP') or det_lan_ip).strip()
    lan_cidr = (overrides.get('LAN_CIDR') or overrides.get('VPNAAS_LAN_CIDR') or det_lan_cidr).strip()
    lan_cidr = str(ipaddress.IPv4Network(lan_cidr, strict=False))
    if lan_cidr == '0.0.0.0/0':
        raise ValueError('LAN_CIDR cannot be 0.0.0.0/0')

    full_dns_raw = (overrides.get('FULL_DNS') or overrides.get('VPNAAS_FULL_DNS') or '1.1.1.1,8.8.8.8').strip()
    full_dns = ','.join(str(ipaddress.IPv4Address(x.strip())) for x in full_dns_raw.split(',') if x.strip())

    return {
        'PUBLIC_IP': str(ipaddress.IPv4Address(detected_pub_ip)),
        'PUBLIC_IF': pub_if,
        'BIND_IP': str(ipaddress.IPv4Address(bind_ip)),
        'LAN_CIDR': lan_cidr,
        'LAN_IF': lan_if,
        'LAN_IP': str(ipaddress.IPv4Address(lan_ip)),
        'FULL_DNS': full_dns or '1.1.1.1,8.8.8.8',
        'HAS_PRIVATE_NIC': lan_choice is not None,
        'PUBLIC_IP_IS_GLOBAL': _is_global_ipv4(detected_pub_ip),
    }


def _render_backend_env(net: dict, db_path: str, pool_cidr: str, extra: dict) -> str:
    lines = [
        f"VPNAAS_PUBLIC_IP={net['PUBLIC_IP']}",
        f"VPNAAS_PUBLIC_IF={net['PUBLIC_IF']}",
    ]
    if net.get('BIND_IP') and net['BIND_IP'] != net['PUBLIC_IP']:
        lines.append(f"VPNAAS_BIND_IP={net['BIND_IP']}")
    lines += [
        f"VPNAAS_LAN_CIDR={net['LAN_CIDR']}",
        f"VPNAAS_LAN_IF={net['LAN_IF']}",
        f"VPNAAS_LAN_IP={net['LAN_IP']}",
        f"VPNAAS_FULL_DNS={net['FULL_DNS']}",
        f"VPNAAS_DB={db_path}",
        'VPNAAS_ROUTE_AUTO=1',
        'VPNAAS_USE_VICI=1',
    ]
    for mk in ('VPNAAS_REGION', 'VPNAAS_TENANT_ID', 'VPNAAS_INSTANCE_ID'):
        val = (extra.get(mk) or '').strip()
        if val and META_VAL_RE.fullmatch(val):
            lines.append(f'{mk}={val}')
    for ok in ('VPNAAS_POOL_ALLOW_CUSTOM', 'VPNAAS_PUBLIC_DOCS', 'VPNAAS_SESSION_LIMIT', 'VPNAAS_PIN_NETWORK'):
        val = (extra.get(ok) or '').strip()
        if val in ('0', '1'):
            lines.append(f'{ok}={val}')
    if pool_cidr:
        lines.append(f'VPNAAS_POOL_CIDR={pool_cidr}')
    return '\n'.join(lines) + '\n'


def _wipe_per_vm_state(
    env_path: Path,
    key_path: Path,
    db_path: Path,
    backup_dir: Path,
    firewall_nft: Path,
    keep_db: bool = False,
):
    import pki
    import vpn

    targets = [
        env_path,
        key_path,
        pki.ca_key_path(),
        pki.ca_cert_path(),
        pki.server_key_path(),
        pki.server_cert_path(),
        pki.crl_path(),
        vpn.CONF,
        firewall_nft,
    ]
    if not keep_db:
        targets.extend([
            db_path,
            Path(str(db_path) + '-wal'),
            Path(str(db_path) + '-shm'),
        ])
    for p in targets:
        try:
            if p.exists():
                p.unlink()
        except OSError:
            pass
    if backup_dir.exists():
        for child in backup_dir.iterdir():
            try:
                if child.is_dir():
                    shutil.rmtree(child)
                else:
                    child.unlink()
            except OSError:
                pass


def _pki_complete() -> bool:
    import pki
    return all(
        p.exists() and p.stat().st_size > 0
        for p in (pki.ca_key_path(), pki.ca_cert_path(), pki.server_key_path(), pki.server_cert_path())
    )


def _strip_secret_from_bootstrap_env(path: Path):
    if not path.exists():
        return
    kept = []
    for line in path.read_text(encoding='utf-8').splitlines():
        k = line.split('=', 1)[0].strip() if '=' in line else ''
        if k in ('VPNAAS_API_KEY', 'VPNAAS_BOOTSTRAP_API_KEY'):
            continue
        kept.append(line)
    if kept:
        _atomic_write(path, '\n'.join(kept) + '\n', mode=0o600)
    else:
        try:
            path.unlink()
        except OSError:
            pass


def bootstrap(
    env_path: Path = DEFAULT_ENV_PATH,
    key_path: Path = DEFAULT_KEY_PATH,
    bootstrap_env_path: Path = DEFAULT_BOOTSTRAP_ENV,
    identity_path: Path = DEFAULT_IDENTITY_PATH,
    golden_marker: Path = DEFAULT_GOLDEN_MARKER,
    backup_dir: Path = DEFAULT_BACKUP_DIR,
    firewall_nft: Path = DEFAULT_FIREWALL_NFT,
    db_path: Path = Path('/var/lib/vpnaas/data.sqlite3'),
    routes_addrs_fn=_kernel_routes_and_addrs,
    identity_fn=read_vm_identity,
    metadata_ip_fn=fetch_metadata_public_ip,
    wait_network_sec: int = 15,
    apply_runtime_guards: bool = True,
) -> dict:
    """Idempotent boot bootstrap for golden images, direct VM snapshots, and normal reboots."""
    import pki
    import pool

    prev_identity = {}
    if identity_path.exists():
        try:
            prev_identity = json.loads(identity_path.read_text(encoding='utf-8'))
        except Exception:
            prev_identity = {}
    curr_identity = identity_fn()
    marker_exists = golden_marker.exists()
    is_clone, reason = is_clone_or_first_boot(
        prev_identity, curr_identity, marker_exists, env_path.exists(), _pki_complete()
    )

    # Wait briefly for DHCP / cloud-init networking on boot.
    main_routes, addresses = None, None
    deadline = time.monotonic() + max(0, wait_network_sec)
    last_err = None
    while True:
        try:
            main_routes, addresses = routes_addrs_fn()
            if any(
                info.get('family') == 'inet' and info.get('scope') == 'global'
                for a in addresses if not VIRTUAL_DEV.match(a.get('ifname', ''))
                for info in a.get('addr_info', [])
            ):
                break
        except Exception as exc:
            last_err = exc
        if time.monotonic() >= deadline:
            if main_routes is None or addresses is None:
                raise RuntimeError(f'Network not ready during bootstrap: {last_err}')
            break
        time.sleep(1)

    boot_overrides = _parse_env_file(bootstrap_env_path)
    old_env = {} if is_clone else _parse_env_file(env_path)
    if not is_clone and old_env.get('VPNAAS_DB'):
        db_path = Path(old_env['VPNAAS_DB'])

    actions = []
    if is_clone:
        _log(f'New VM clone / golden image detected ({reason}); provisioning fresh identity, PKI, pool, and network config')
        keep_db = (boot_overrides.get('VPNAAS_KEEP_DB_ON_CLONE') or os.environ.get('VPNAAS_KEEP_DB_ON_CLONE')) == '1'
        _wipe_per_vm_state(env_path, key_path, db_path, backup_dir, firewall_nft, keep_db=keep_db)
        actions.append('wiped-builder-state')

    pin_network = (old_env.get('VPNAAS_PIN_NETWORK') == '1') or (boot_overrides.get('VPNAAS_PIN_NETWORK') == '1')
    overrides = {}
    if pin_network and not is_clone:
        for k in ('VPNAAS_PUBLIC_IP', 'VPNAAS_PUBLIC_IF', 'VPNAAS_BIND_IP', 'VPNAAS_LAN_CIDR', 'VPNAAS_LAN_IF', 'VPNAAS_LAN_IP', 'VPNAAS_FULL_DNS'):
            if old_env.get(k):
                overrides[k] = old_env[k]
    elif not is_clone and old_env.get('VPNAAS_FULL_DNS'):
        overrides['VPNAAS_FULL_DNS'] = old_env['VPNAAS_FULL_DNS']
    # Cloud-init bootstrap.env overrides win cleanly when present.
    for k in ('PUBLIC_IP', 'PUBLIC_IF', 'BIND_IP', 'LAN_CIDR', 'LAN_IF', 'LAN_IP', 'FULL_DNS',
              'VPNAAS_PUBLIC_IP', 'VPNAAS_PUBLIC_IF', 'VPNAAS_BIND_IP', 'VPNAAS_LAN_CIDR', 'VPNAAS_LAN_IF', 'VPNAAS_LAN_IP', 'VPNAAS_FULL_DNS'):
        if boot_overrides.get(k):
            overrides[k] = boot_overrides[k]

    net = detect_network(main_routes, addresses, overrides=overrides, metadata_ip_fn=metadata_ip_fn)
    # On a normal reboot of a Floating-IP/NAT VM, never downgrade a valid global PUBLIC_IP to RFC1918 if metadata hiccups.
    if not is_clone and not net['PUBLIC_IP_IS_GLOBAL'] and _is_global_ipv4(old_env.get('VPNAAS_PUBLIC_IP', '')):
        net['PUBLIC_IP'] = old_env['VPNAAS_PUBLIC_IP']
        net['PUBLIC_IP_IS_GLOBAL'] = True

    # Preserve or generate API key
    injected_key = (boot_overrides.get('VPNAAS_BOOTSTRAP_API_KEY') or boot_overrides.get('VPNAAS_API_KEY') or '').strip()
    if is_clone or not key_path.exists() or not _read_text(key_path):
        api_key = injected_key if len(injected_key) >= 16 else secrets.token_hex(32)
        _atomic_write(key_path, api_key + '\n', mode=0o600)
        actions.append('generated-api-key')
        if injected_key:
            _strip_secret_from_bootstrap_env(bootstrap_env_path)

    # Select or preserve VIP pool
    pool_cidr = old_env.get('VPNAAS_POOL_CIDR', '').strip() if not is_clone else ''
    if not pool_cidr:
        custom_pool = (boot_overrides.get('VPNAAS_POOL_CIDR') or '').strip()
        if custom_pool:
            pool_cidr = custom_pool
        else:
            occupied = [r['dst'] for r in main_routes if r.get('dst') and r['dst'] != 'default']
            if net['LAN_CIDR'] != LAN_PLACEHOLDER:
                occupied.append(net['LAN_CIDR'])
            pool_cidr = pool.choose(occupied)
        actions.append(f'selected-pool:{pool_cidr}')

    extra = {}
    for mk in ('VPNAAS_REGION', 'VPNAAS_TENANT_ID', 'VPNAAS_INSTANCE_ID',
               'VPNAAS_POOL_ALLOW_CUSTOM', 'VPNAAS_PUBLIC_DOCS', 'VPNAAS_SESSION_LIMIT', 'VPNAAS_PIN_NETWORK'):
        short = mk.replace('VPNAAS_', '')
        extra[mk] = boot_overrides.get(mk) or boot_overrides.get(short) or old_env.get(mk) or ''
    if not extra['VPNAAS_INSTANCE_ID'] and curr_identity.get('cloud_instance_id'):
        extra['VPNAAS_INSTANCE_ID'] = curr_identity['cloud_instance_id']

    new_env_text = _render_backend_env(net, str(db_path), pool_cidr, extra)
    old_env_text = env_path.read_text(encoding='utf-8') if env_path.exists() else ''
    if new_env_text != old_env_text:
        _atomic_write(env_path, new_env_text, mode=0o600)
        actions.append('updated-backend-env')

    # Temporarily expose resolved env for pki / network / tuning calls without leaking into library callers.
    saved_env = {}
    written_keys = []
    for line in new_env_text.splitlines():
        if '=' in line:
            k, v = line.split('=', 1)
            saved_env[k] = os.environ.get(k)
            written_keys.append(k)
            os.environ[k] = v

    try:
        # PKI initialization / server-cert IP reconciliation
        extra_sans_raw = (boot_overrides.get('VPNAAS_EXTRA_SANS') or '').strip()
        extra_sans = [s.strip() for s in extra_sans_raw.split(',') if s.strip()] if extra_sans_raw else None
        if is_clone or not _pki_complete():
            pki.ensure_ca()
            pki.rotate_server_cert(public_ip=net['PUBLIC_IP'], extra_sans=extra_sans)
            actions.append(f"issued-pki:{net['PUBLIC_IP']}")
        else:
            srv = pki.server_info()
            if not srv.get('present') or net['PUBLIC_IP'] not in (srv.get('san_ips') or []):
                _log(f"Public IP changed to {net['PUBLIC_IP']}; rotating server cert under existing Root CA")
                pki.rotate_server_cert(public_ip=net['PUBLIC_IP'], extra_sans=extra_sans)
                actions.append(f"rotated-server-cert:{net['PUBLIC_IP']}")

        if marker_exists:
            try:
                golden_marker.unlink()
            except OSError:
                pass
        _atomic_write(identity_path, json.dumps(curr_identity, indent=2) + '\n', mode=0o600)

        if apply_runtime_guards and os.environ.get('VPNAAS_DRY_RUN') != '1':
            try:
                import network
                network.ensure_public_routing(routes=main_routes)
                actions.append('ensured-public-routing')
            except Exception as exc:
                _log(f'warning: ensure_public_routing failed: {exc}')
            try:
                import tuning
                tuning.reconcile()
            except Exception:
                pass
    finally:
        for k in written_keys:
            if saved_env[k] is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = saved_env[k]

    if not net['PUBLIC_IP_IS_GLOBAL']:
        _log(f"WARNING: detected PUBLIC_IP={net['PUBLIC_IP']} is private; attach Floating IP or set VPNAAS_PUBLIC_IP in /etc/vpnaas/bootstrap.env and restart vpnaas-bootstrap")
    _log(f"Ready: clone={is_clone} ({reason}) public={net['PUBLIC_IP']} via {net['PUBLIC_IF']} (bind={net['BIND_IP']}) lan={net['LAN_CIDR']} pool={pool_cidr}")
    return {
        'is_clone': is_clone,
        'reason': reason,
        'network': net,
        'pool_cidr': pool_cidr,
        'actions': actions,
    }


def seal_for_golden_image(
    env_path: Path = DEFAULT_ENV_PATH,
    key_path: Path = DEFAULT_KEY_PATH,
    bootstrap_env_path: Path = DEFAULT_BOOTSTRAP_ENV,
    identity_path: Path = DEFAULT_IDENTITY_PATH,
    golden_marker: Path = DEFAULT_GOLDEN_MARKER,
    backup_dir: Path = DEFAULT_BACKUP_DIR,
    firewall_nft: Path = DEFAULT_FIREWALL_NFT,
    db_path: Path = Path('/var/lib/vpnaas/data.sqlite3'),
    stop_services: bool = True,
) -> dict:
    """Sanitize a VM before taking a golden snapshot image (sysprep for VPNaaS)."""
    if stop_services and os.environ.get('VPNAAS_DRY_RUN') != '1':
        for unit in ('vpnaas-reconcile.timer', 'vpnaas-offload.timer', 'vpnaas-api.service', 'strongswan.service'):
            subprocess.run(['systemctl', 'stop', unit], check=False, capture_output=True, text=True, timeout=15)

    _wipe_per_vm_state(env_path, key_path, db_path, backup_dir, firewall_nft, keep_db=False)
    for extra_file in (bootstrap_env_path, identity_path):
        try:
            if extra_file.exists():
                extra_file.unlink()
        except OSError:
            pass
    _atomic_write(golden_marker, 'sealed-for-golden-image\n', mode=0o600)
    _log('VM sealed for golden image snapshot. Next boot will generate unique API key, Root CA, Server Cert, VIP pool, and network config.')
    return {'sealed': True, 'marker': str(golden_marker)}


def record_current_identity(identity_path: Path = DEFAULT_IDENTITY_PATH, identity_fn=read_vm_identity) -> dict:
    ident = identity_fn()
    _atomic_write(identity_path, json.dumps(ident, indent=2) + '\n', mode=0o600)
    return ident


if __name__ == '__main__':
    if '--seal' in sys.argv:
        seal_for_golden_image()
    elif '--record-identity' in sys.argv:
        print(json.dumps(record_current_identity()))
    else:
        bootstrap()
