"""X.509 Certificate Authority, Server Cert Rotation, Client/Site Cert Issuance, PKCS#12 & CRL.

Compatible with existing strongSwan PKI paths created by install.sh:
- CA key:      /var/lib/vpnaas/ca-key.pem (override: VPNAAS_CA_KEY)
- CA cert:     /etc/swanctl/x509ca/ca.pem (override base: VPNAAS_SWANCTL_DIR)
- Server key:  /etc/swanctl/private/server-key.pem
- Server cert: /etc/swanctl/x509/server.pem
- CRL:         /etc/swanctl/x509crl/ca.crl
"""
import datetime
import ipaddress
import os
import tempfile
from pathlib import Path
from fastapi import HTTPException

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


NO_EXPIRATION_UTC = datetime.datetime(9999, 12, 31, 23, 59, 59, tzinfo=datetime.timezone.utc)


def _now_utc():
    return datetime.datetime.now(datetime.timezone.utc)


def swanctl_dir() -> Path:
    return Path(os.environ.get('VPNAAS_SWANCTL_DIR', '/etc/swanctl'))


def ca_key_path() -> Path:
    return Path(os.environ.get('VPNAAS_CA_KEY', '/var/lib/vpnaas/ca-key.pem'))


def ca_cert_path() -> Path:
    return swanctl_dir() / 'x509ca' / 'ca.pem'


def server_key_path() -> Path:
    return swanctl_dir() / 'private' / 'server-key.pem'


def server_cert_path() -> Path:
    return swanctl_dir() / 'x509' / 'server.pem'


def crl_path() -> Path:
    return swanctl_dir() / 'x509crl' / 'ca.crl'


def _atomic_bytes(path: Path, data: bytes, mode: int = 0o600):
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(dir=path.parent)
    try:
        try:
            os.fchmod(fd, mode)
        except (AttributeError, OSError):
            pass
        with os.fdopen(fd, 'wb') as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(name, path)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def _gen_rsa_key(key_size: int = 3072):
    return rsa.generate_private_key(public_exponent=65537, key_size=key_size)


def _key_to_pem(key) -> bytes:
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )


def _cert_to_pem(cert) -> bytes:
    return cert.public_bytes(serialization.Encoding.PEM)


def _load_ca():
    key_p, cert_p = ca_key_path(), ca_cert_path()
    if not key_p.exists() or not cert_p.exists():
        raise HTTPException(503, 'PKI CA not initialized on gateway')
    ca_key = serialization.load_pem_private_key(key_p.read_bytes(), password=None)
    ca_cert = x509.load_pem_x509_certificate(cert_p.read_bytes())
    return ca_key, ca_cert


def ensure_ca(common_name: str = 'VPNaaS CA', lifetime_days: int = 3650):
    """Initialize CA if absent; never overwrite an existing CA."""
    key_p, cert_p = ca_key_path(), ca_cert_path()
    if key_p.exists() and cert_p.exists():
        return _load_ca()
    if key_p.exists() != cert_p.exists():
        raise HTTPException(503, 'Incomplete PKI CA state; restore backup before proceeding')
    ca_key = _gen_rsa_key(3072)
    now = _now_utc()
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=lifetime_days))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False)
        .sign(ca_key, hashes.SHA256())
    )
    _atomic_bytes(key_p, _key_to_pem(ca_key), mode=0o600)
    _atomic_bytes(cert_p, _cert_to_pem(ca_cert), mode=0o644)
    return ca_key, ca_cert


def cert_metadata(pem_bytes: bytes) -> dict:
    cert = x509.load_pem_x509_certificate(pem_bytes)
    now = _now_utc()
    not_before = cert.not_valid_before_utc
    not_after = cert.not_valid_after_utc
    no_exp = not_after.year >= 9999
    days_remaining = None if no_exp else int((not_after - now).total_seconds() // 86400)
    san_ips, san_dns, san_emails = [], [], []
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        san_ips = [str(ip) for ip in san.get_values_for_type(x509.IPAddress)]
        san_dns = list(san.get_values_for_type(x509.DNSName))
        san_emails = list(san.get_values_for_type(x509.RFC822Name))
    except x509.ExtensionNotFound:
        pass
    fp = cert.fingerprint(hashes.SHA256()).hex()
    colon_fp = ':'.join(fp[i:i + 2] for i in range(0, len(fp), 2)).upper()
    return {
        'subject': cert.subject.rfc4514_string(),
        'issuer': cert.issuer.rfc4514_string(),
        'serial': format(cert.serial_number, 'x'),
        'not_before': not_before.strftime('%Y-%m-%dT%H:%M:%SZ'),
        'not_after': not_after.strftime('%Y-%m-%dT%H:%M:%SZ'),
        'no_expiration': no_exp,
        'days_remaining': days_remaining,
        'expired': False if no_exp else (now >= not_after),
        'san_ips': san_ips,
        'san_dns': san_dns,
        'san_emails': san_emails,
        'sha256_fingerprint': colon_fp,
    }


def ca_info() -> dict:
    p = ca_cert_path()
    if not p.exists():
        return {'present': False, 'has_private_key': ca_key_path().exists()}
    meta = cert_metadata(p.read_bytes())
    return {'present': True, 'has_private_key': ca_key_path().exists(), **meta}


def ca_pem() -> str:
    p = ca_cert_path()
    return p.read_text(encoding='utf-8') if p.exists() else ''


def server_info() -> dict:
    p = server_cert_path()
    if not p.exists():
        return {'present': False, 'has_private_key': server_key_path().exists()}
    meta = cert_metadata(p.read_bytes())
    return {'present': True, 'has_private_key': server_key_path().exists(), **meta}


def _build_san_entries(values):
    entries = []
    seen = set()
    for val in values:
        if not val or val in seen:
            continue
        seen.add(val)
        try:
            entries.append(x509.IPAddress(ipaddress.ip_address(val)))
            continue
        except ValueError:
            pass
        if '@' in val:
            entries.append(x509.RFC822Name(val))
        else:
            entries.append(x509.DNSName(val))
    return entries


def rotate_server_cert(public_ip: str = None, extra_sans=None, validity_days: int = 825) -> dict:
    """Issue a fresh server certificate signed by the existing CA and reload strongSwan creds."""
    if not isinstance(validity_days, int) or isinstance(validity_days, bool) or not 30 <= validity_days <= 1095:
        raise HTTPException(422, 'validity_days must be an integer 30..1095')
    from vpn import public_ip as default_pub
    addr = public_ip or default_pub()
    try:
        ipaddress.IPv4Address(addr)
    except ValueError:
        raise HTTPException(422, 'Invalid server public IPv4')
    sans = [addr]
    for item in (extra_sans or []):
        if not isinstance(item, str) or len(item) > 253:
            raise HTTPException(422, 'Invalid SAN entry')
        sans.append(item.strip())

    ca_key, ca_cert = ensure_ca()
    srv_key = _gen_rsa_key(3072)
    now = _now_utc()
    srv_cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, addr)]))
        .issuer_name(ca_cert.subject)
        .public_key(srv_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=validity_days))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .add_extension(x509.SubjectAlternativeName(_build_san_entries(sans)), critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )
    _atomic_bytes(server_key_path(), _key_to_pem(srv_key), mode=0o600)
    cert_bytes = _cert_to_pem(srv_cert)
    _atomic_bytes(server_cert_path(), cert_bytes, mode=0o644)
    reload_creds()
    return {'rotated': True, **cert_metadata(cert_bytes)}


def issue_leaf_cert(common_name: str, san: str, target_type: str = 'user', validity_days: int = 365, no_expiration: bool = False):
    """Issue a client or S2S site X.509 certificate signed by the gateway CA.

    When no_expiration=True (or validity_days is None / 0), uses RFC 5280 §4.1.2.5
    non-expiring sentinel 9999-12-31T23:59:59Z.
    """
    is_no_exp = bool(no_expiration) or validity_days in (None, 0)
    if not is_no_exp:
        if not isinstance(validity_days, int) or isinstance(validity_days, bool) or not 1 <= validity_days <= 3650:
            raise HTTPException(422, 'validity_days must be an integer 1..3650 (or set no_expiration=true)')
    ca_key, ca_cert = ensure_ca()
    leaf_key = _gen_rsa_key(2048 if target_type == 'user' else 3072)
    now = _now_utc()
    not_after = NO_EXPIRATION_UTC if is_no_exp else (now + datetime.timedelta(days=validity_days))
    ekus = [ExtendedKeyUsageOID.CLIENT_AUTH]
    if target_type == 'site':
        ekus.append(ExtendedKeyUsageOID.SERVER_AUTH)
    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)]))
        .issuer_name(ca_cert.subject)
        .public_key(leaf_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(not_after)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.ExtendedKeyUsage(ekus), critical=False)
        .add_extension(x509.SubjectAlternativeName(_build_san_entries([san])), critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )
    cert_pem_bytes = _cert_to_pem(cert)
    key_pem_bytes = _key_to_pem(leaf_key)
    meta = cert_metadata(cert_pem_bytes)
    return cert_pem_bytes.decode('utf-8'), key_pem_bytes.decode('utf-8'), meta


def build_pkcs12(cert_pem: str, key_pem: str, ca_cert_pem: str, friendly_name: str, passphrase: str = '') -> bytes:
    cert = x509.load_pem_x509_certificate(cert_pem.encode('utf-8'))
    key = serialization.load_pem_private_key(key_pem.encode('utf-8'), password=None)
    cas = [x509.load_pem_x509_certificate(ca_cert_pem.encode('utf-8'))] if ca_cert_pem else None
    enc = (
        serialization.BestAvailableEncryption(passphrase.encode('utf-8'))
        if passphrase
        else serialization.NoEncryption()
    )
    return pkcs12.serialize_key_and_certificates(
        name=friendly_name.encode('utf-8'),
        key=key,
        cert=cert,
        cas=cas,
        encryption_algorithm=enc,
    )


def rebuild_crl(revoked_rows: list) -> bytes:
    """Regenerate X.509 CRL signed by CA and install into strongSwan x509crl/."""
    ca_key, ca_cert = ensure_ca()
    now = _now_utc()
    builder = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(ca_cert.subject)
        .last_update(now)
        .next_update(now + datetime.timedelta(days=365))
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
            critical=False,
        )
    )
    for item in revoked_rows:
        serial_hex = item.get('serial')
        if not serial_hex:
            continue
        rev_at = now
        if item.get('revoked_at'):
            try:
                rev_at = datetime.datetime.fromisoformat(item['revoked_at'].replace('Z', '+00:00'))
            except ValueError:
                rev_at = now
        revoked_cert = (
            x509.RevokedCertificateBuilder()
            .serial_number(int(serial_hex, 16))
            .revocation_date(rev_at)
            .build()
        )
        builder = builder.add_revoked_certificate(revoked_cert)
    crl = builder.sign(private_key=ca_key, algorithm=hashes.SHA256())
    pem = crl.public_bytes(serialization.Encoding.PEM)
    _atomic_bytes(crl_path(), pem, mode=0o644)
    reload_creds()
    return pem


def read_crl_pem() -> str:
    p = crl_path()
    return p.read_text(encoding='utf-8') if p.exists() else ''


def reload_creds():
    if os.environ.get('VPNAAS_DRY_RUN') == '1':
        return
    try:
        import vpn
        vpn.run(['swanctl', '--load-creds'], timeout=12)
    except Exception:
        # Let caller continue if daemon is restarting; full apply will also reload.
        pass
