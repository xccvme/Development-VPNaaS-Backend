#!/usr/bin/env python3
"""Build deterministic embedded source payload. No runtime files are globbed."""
import base64
import gzip
import hashlib
import io
from pathlib import Path
import tarfile

root = Path(__file__).resolve().parent
files = (
    'app.py',
    'auth.py',
    'bootstrap.py',
    'network.py',
    'pki.py',
    'pool.py',
    'profiles.py',
    'requirements.txt',
    'routing.py',
    'runtime.py',
    'sessions.py',
    'spoke.py',
    'store.py',
    'tuning.py',
    'vendors.py',
    'vici_client.py',
    'vpn.py',
)
archive = io.BytesIO()
with tarfile.open(fileobj=archive, mode='w', format=tarfile.USTAR_FORMAT) as tar:
    for name in files:
        data = (root / 'src' / name).read_bytes().replace(b'\r\n', b'\n')
        info = tarfile.TarInfo(name)
        info.size = len(data)
        info.mode = 0o600
        info.mtime = 0
        info.uid = info.gid = 0
        info.uname = info.gname = ''
        tar.addfile(info, io.BytesIO(data))
payload = base64.encodebytes(gzip.compress(archive.getvalue(), mtime=0)).decode()
text = (root / 'install.template.sh').read_text(encoding='utf-8').replace('\r\n', '\n')
assert text.count('@@PAYLOAD@@') == 1
out = root / 'install.sh'
out.write_text(text.replace('@@PAYLOAD@@', payload.rstrip()), encoding='utf-8', newline='\n')
out.chmod(0o755)
print('install.sh SHA256 ' + hashlib.sha256(out.read_bytes()).hexdigest())
