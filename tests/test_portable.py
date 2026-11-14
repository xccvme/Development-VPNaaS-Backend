import os, subprocess, sys, json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
def test_deployment_configuration_is_portable():
    env = dict(os.environ, VPNAAS_DB=':memory:', VPNAAS_PUBLIC_IP='203.0.113.99', VPNAAS_PUBLIC_IF='wan0', VPNAAS_LAN_CIDR='172.20.0.0/24', VPNAAS_LAN_IF='lan0', VPNAAS_LAN_IP='172.20.0.2', PYTHONPATH=str(ROOT/'src'))
    code = """import vpn, store; u=dict(id=1,username='qa',password='test-only-pass',enabled=True,allowed_cidrs=['172.20.0.0/24'],traffic_mode='full');t=vpn.render([],[u]);r=vpn.firewall([],[u],[]);assert 'local_addrs = 203.0.113.99' in t;assert 'snat to 203.0.113.99' in r;assert 'oifname \"lan0\" snat to 172.20.0.2' in r;assert store.validate('users',dict(username='qa',password='test-only-pass'))['allowed_cidrs']==['172.20.0.0/24']"""
    p=subprocess.run([sys.executable,'-c',code],env=env,capture_output=True,text=True)
    assert p.returncode==0,p.stderr
