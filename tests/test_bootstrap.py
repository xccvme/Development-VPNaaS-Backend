"""Tests for golden-image (snapshot) bootstrap, clone detection, Floating IP bind_ip, and split-tunnel defaults."""
import json
from pathlib import Path

import bootstrap
import pki
import vpn


def _routes_2nic(pub_if, pub_ip, pub_gw, lan_if, lan_ip, lan_cidr):
    routes = [
        {'dst': 'default', 'gateway': lan_ip.rsplit('.', 1)[0] + '.1', 'dev': lan_if, 'metric': 200},
        {'dst': 'default', 'gateway': pub_gw, 'dev': pub_if, 'prefsrc': pub_ip, 'metric': 1002},
        {'dst': lan_cidr, 'dev': lan_if, 'protocol': 'kernel', 'scope': 'link', 'prefsrc': lan_ip},
    ]
    addrs = [
        {'ifname': 'lo', 'addr_info': [{'family': 'inet', 'local': '127.0.0.1', 'prefixlen': 8, 'scope': 'host'}]},
        {'ifname': pub_if, 'addr_info': [{'family': 'inet', 'local': pub_ip, 'prefixlen': 24, 'scope': 'global'}]},
        {'ifname': lan_if, 'addr_info': [{'family': 'inet', 'local': lan_ip, 'prefixlen': 24, 'scope': 'global'}]},
    ]
    return routes, addrs


def _setup_paths(tmp_path, monkeypatch):
    monkeypatch.setenv('VPNAAS_SWANCTL_DIR', str(tmp_path / 'swanctl'))
    monkeypatch.setenv('VPNAAS_CA_KEY', str(tmp_path / 'var' / 'ca-key.pem'))
    monkeypatch.setattr(vpn, 'CONF', tmp_path / 'swanctl' / 'conf.d' / 'vpnaas.conf')
    return {
        'env_path': tmp_path / 'etc' / 'backend.env',
        'key_path': tmp_path / 'etc' / 'api.key',
        'bootstrap_env_path': tmp_path / 'etc' / 'bootstrap.env',
        'identity_path': tmp_path / 'var' / 'instance-identity.json',
        'golden_marker': tmp_path / 'var' / '.golden-image',
        'backup_dir': tmp_path / 'backups',
        'firewall_nft': tmp_path / 'opt' / 'firewall.nft',
        'db_path': tmp_path / 'var' / 'data.sqlite3',
    }


def test_sealed_golden_image_first_boot_provisions_fresh_state(tmp_path, monkeypatch):
    paths = _setup_paths(tmp_path, monkeypatch)
    # 1. Simulate builder VM being sealed before snapshot
    paths['db_path'].parent.mkdir(parents=True, exist_ok=True)
    paths['db_path'].write_text('builder-stale-db')
    paths['key_path'].parent.mkdir(parents=True, exist_ok=True)
    paths['key_path'].write_text('builder-old-key\n')
    (paths['backup_dir'] / 'old').mkdir(parents=True, exist_ok=True)
    (paths['backup_dir'] / 'old' / 'secret').write_text('old-ca')

    seal = bootstrap.seal_for_golden_image(**paths, stop_services=False)
    assert seal['sealed'] is True
    assert paths['golden_marker'].exists()
    assert not paths['db_path'].exists()
    assert not paths['key_path'].exists()
    assert not any(paths['backup_dir'].iterdir())

    # 2. Boot new Customer VM #1 from that golden snapshot (different IP, different VPC, cloud-init metadata)
    vm1_routes, vm1_addrs = _routes_2nic('ens3', '38.47.85.201', '38.47.85.254', 'ens4', '10.60.0.10', '10.60.0.0/24')
    vm1_id = {'dmi_uuid': '11111111-aaaa-bbbb-cccc-111111111111', 'cloud_instance_id': 'i-customer-001', 'machine_id': 'aaaa1111'}
    paths['bootstrap_env_path'].write_text('VPNAAS_REGION=id-jkt-1\nVPNAAS_TENANT_ID=tenant-alpha\nVPNAAS_API_KEY=portal-injected-key-1234567890\n')

    res = bootstrap.bootstrap(
        **paths,
        routes_addrs_fn=lambda: (vm1_routes, vm1_addrs),
        identity_fn=lambda: vm1_id,
        metadata_ip_fn=lambda: '',
        wait_network_sec=0,
        apply_runtime_guards=False,
    )
    assert res['is_clone'] is True and res['reason'] == 'golden-image-marker'
    assert not paths['golden_marker'].exists()
    assert paths['key_path'].read_text().strip() == 'portal-injected-key-1234567890'
    # Secret must be stripped from bootstrap.env after ingestion!
    assert not paths['bootstrap_env_path'].exists() or 'portal-injected-key' not in paths['bootstrap_env_path'].read_text()

    env_map = bootstrap._parse_env_file(paths['env_path'])
    assert env_map['VPNAAS_PUBLIC_IP'] == '38.47.85.201'
    assert env_map['VPNAAS_PUBLIC_IF'] == 'ens3'
    assert env_map['VPNAAS_LAN_CIDR'] == '10.60.0.0/24'
    assert env_map['VPNAAS_LAN_IF'] == 'ens4'
    assert env_map['VPNAAS_REGION'] == 'id-jkt-1'
    assert env_map['VPNAAS_TENANT_ID'] == 'tenant-alpha'
    assert env_map['VPNAAS_INSTANCE_ID'] == 'i-customer-001'
    assert 'VPNAAS_BIND_IP' not in env_map  # direct public IP -> no separate bind_ip needed
    assert env_map['VPNAAS_POOL_CIDR'].startswith('172.31.')

    ca1 = pki.ca_info()
    srv1 = pki.server_info()
    assert ca1['present'] is True
    assert srv1['present'] is True and '38.47.85.201' in srv1['san_ips']


def test_direct_unsealed_snapshot_clone_auto_rotates_ca_key_and_db(tmp_path, monkeypatch):
    """Even if operator snapshots a live VM WITHOUT running vpnaas-prepare-image,
    a cloned VM with a new DMI UUID / cloud instance-id MUST get fresh CA, Server Cert, API key, and clean DB!
    """
    paths = _setup_paths(tmp_path, monkeypatch)
    vm1_routes, vm1_addrs = _routes_2nic('ens3', '38.47.85.185', '38.47.85.254', 'ens4', '172.16.50.240', '172.16.50.0/24')
    vm1_id = {'dmi_uuid': 'aaaa0000-0000-0000-0000-000000000001', 'cloud_instance_id': 'i-builder-1', 'machine_id': 'm1'}

    bootstrap.bootstrap(
        **paths,
        routes_addrs_fn=lambda: (vm1_routes, vm1_addrs),
        identity_fn=lambda: vm1_id,
        metadata_ip_fn=lambda: '',
        wait_network_sec=0,
        apply_runtime_guards=False,
    )
    vm1_key = paths['key_path'].read_text().strip()
    vm1_ca_fp = pki.ca_info()['sha256_fingerprint']
    paths['db_path'].write_text('builder-test-user-data')

    # Normal reboot on SAME VM #1: MUST preserve DB, API key, and Root CA!
    res_reboot = bootstrap.bootstrap(
        **paths,
        routes_addrs_fn=lambda: (vm1_routes, vm1_addrs),
        identity_fn=lambda: vm1_id,
        metadata_ip_fn=lambda: '',
        wait_network_sec=0,
        apply_runtime_guards=False,
    )
    assert res_reboot['is_clone'] is False and res_reboot['reason'] == 'same-instance'
    assert paths['key_path'].read_text().strip() == vm1_key
    assert pki.ca_info()['sha256_fingerprint'] == vm1_ca_fp
    assert paths['db_path'].read_text() == 'builder-test-user-data'

    # Now simulate OpenStack launching VM #2 from direct snapshot of VM #1 (new DMI UUID + new cloud instance-id + new IP + new VPC!)
    vm2_routes, vm2_addrs = _routes_2nic('ens3', '38.47.85.222', '38.47.85.254', 'ens4', '10.88.0.5', '10.88.0.0/24')
    vm2_id = {'dmi_uuid': 'bbbb0000-0000-0000-0000-000000000002', 'cloud_instance_id': 'i-customer-2', 'machine_id': 'm2'}

    res_clone = bootstrap.bootstrap(
        **paths,
        routes_addrs_fn=lambda: (vm2_routes, vm2_addrs),
        identity_fn=lambda: vm2_id,
        metadata_ip_fn=lambda: '',
        wait_network_sec=0,
        apply_runtime_guards=False,
    )
    assert res_clone['is_clone'] is True
    assert paths['key_path'].read_text().strip() != vm1_key
    assert pki.ca_info()['sha256_fingerprint'] != vm1_ca_fp
    assert '38.47.85.222' in pki.server_info()['san_ips']
    assert '38.47.85.185' not in pki.server_info()['san_ips']
    assert not paths['db_path'].exists()  # builder test DB wiped cleanly!
    env2 = bootstrap._parse_env_file(paths['env_path'])
    assert env2['VPNAAS_PUBLIC_IP'] == '38.47.85.222'
    assert env2['VPNAAS_LAN_CIDR'] == '10.88.0.0/24'


def test_same_vm_public_ip_change_rotates_only_server_cert_and_keeps_ca(tmp_path, monkeypatch):
    """On a normal reboot where the same VM receives a new public IP (e.g. Floating IP changed),
    Root CA & DB stay untouched while server.pem rotates automatically to cover the new IP.
    """
    paths = _setup_paths(tmp_path, monkeypatch)
    same_id = {'dmi_uuid': 'cccc0000-0000-0000-0000-000000000003', 'cloud_instance_id': 'i-same-vm', 'machine_id': 'm3'}
    r1, a1 = _routes_2nic('ens3', '38.47.85.100', '38.47.85.254', 'ens4', '10.70.0.10', '10.70.0.0/24')
    bootstrap.bootstrap(**paths, routes_addrs_fn=lambda: (r1, a1), identity_fn=lambda: same_id, metadata_ip_fn=lambda: '', wait_network_sec=0, apply_runtime_guards=False)
    ca_fp_before = pki.ca_info()['sha256_fingerprint']
    key_before = paths['key_path'].read_text().strip()

    # Same VM reboots with new public IP 38.47.85.101
    r2, a2 = _routes_2nic('ens3', '38.47.85.101', '38.47.85.254', 'ens4', '10.70.0.10', '10.70.0.0/24')
    res = bootstrap.bootstrap(**paths, routes_addrs_fn=lambda: (r2, a2), identity_fn=lambda: same_id, metadata_ip_fn=lambda: '', wait_network_sec=0, apply_runtime_guards=False)
    assert res['is_clone'] is False
    assert pki.ca_info()['sha256_fingerprint'] == ca_fp_before  # Root CA preserved!
    assert paths['key_path'].read_text().strip() == key_before  # API key preserved!
    assert '38.47.85.101' in pki.server_info()['san_ips']
    assert 'rotated-server-cert:38.47.85.101' in res['actions']


def test_floating_ip_nat_sets_bind_ip_separately_from_public_ip(tmp_path, monkeypatch):
    """When OpenStack assigns a Floating IP (1:1 NAT) to a VM whose WAN NIC holds RFC1918 10.0.0.15,
    bootstrap detects Floating IP via metadata, sets VPNAAS_PUBLIC_IP=floating & VPNAAS_BIND_IP=10.0.0.15,
    and vpn.render() binds local_addrs to 10.0.0.15 while advertising id = floating IP!
    """
    routes = [
        {'dst': 'default', 'gateway': '10.0.0.1', 'dev': 'ens3', 'prefsrc': '10.0.0.15', 'metric': 100},
        {'dst': '10.20.0.0/24', 'dev': 'ens4', 'protocol': 'kernel', 'scope': 'link', 'prefsrc': '10.20.0.5'},
    ]
    addrs = [
        {'ifname': 'ens3', 'addr_info': [{'family': 'inet', 'local': '10.0.0.15', 'prefixlen': 24, 'scope': 'global'}]},
        {'ifname': 'ens4', 'addr_info': [{'family': 'inet', 'local': '10.20.0.5', 'prefixlen': 24, 'scope': 'global'}]},
    ]
    net = bootstrap.detect_network(routes, addrs, metadata_ip_fn=lambda: '38.47.85.209')
    assert net['PUBLIC_IP'] == '38.47.85.209'
    assert net['BIND_IP'] == '10.0.0.15'
    assert net['PUBLIC_IF'] == 'ens3'
    assert net['LAN_CIDR'] == '10.20.0.0/24'

    monkeypatch.setenv('VPNAAS_PUBLIC_IP', '38.47.85.209')
    monkeypatch.setenv('VPNAAS_BIND_IP', '10.0.0.15')
    u = {'id': 1, 'username': 'alice', 'password': 'safe-password-1', 'enabled': True, 'virtual_ip': '172.31.201.2', 'allowed_cidrs': ['10.20.0.0/24'], 'traffic_mode': 'split'}
    s = {'id': 2, 'name': 'site-a', 'address': '%any', 'ike_id': 'site-a@vpnaas', 'psk': 'super-secret-psk-1234', 'subnets': '192.168.10.0/24', 'enabled': True}
    rendered = vpn.render([], [u], sites=[s])
    assert 'local_addrs = 10.0.0.15' in rendered
    assert 'id = 38.47.85.209' in rendered
    assert 'local_ts = 10.20.0.0/24' in rendered  # split-tunnel default: NEVER 0.0.0.0/0!
    assert '0.0.0.0/0' not in rendered

    # Normal reboot with transient metadata failure MUST preserve existing Floating IP 38.47.85.209!
    paths = _setup_paths(tmp_path, monkeypatch)
    same_id = {'dmi_uuid': 'dddd0000-0000-0000-0000-000000000004', 'cloud_instance_id': 'i-fip-vm', 'machine_id': 'm4'}
    bootstrap.bootstrap(**paths, routes_addrs_fn=lambda: (routes, addrs), identity_fn=lambda: same_id, metadata_ip_fn=lambda: '38.47.85.209', wait_network_sec=0, apply_runtime_guards=False)
    res_hiccup = bootstrap.bootstrap(**paths, routes_addrs_fn=lambda: (routes, addrs), identity_fn=lambda: same_id, metadata_ip_fn=lambda: '', wait_network_sec=0, apply_runtime_guards=False)
    assert res_hiccup['network']['PUBLIC_IP'] == '38.47.85.209'
    assert res_hiccup['network']['BIND_IP'] == '10.0.0.15'
    assert '38.47.85.209' in pki.server_info()['san_ips']
