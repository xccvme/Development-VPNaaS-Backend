import network

def test_late_private_route_requires_specific_safe_route():
    default=[{'dst':'default','dev':'ens3','gateway':'203.0.113.254'}]
    assert network.private_route('10.44.0.0/24',default,'ens3') is None
    attached=default+[{'dst':'10.44.0.0/24','dev':'ens9','prefsrc':'10.44.0.2'}]
    assert network.private_route('10.44.0.0/24',attached,'ens3')=='ens9'
    assert network.private_route('10.44.0.0/16',attached,'ens3') is None
    assert network.private_route('10.44.0.0/24',default+[{'dst':'10.44.0.0/24','dev':'ens3'}],'ens3') is None
    assert network.private_route('10.44.0.0/24',attached+[{'dst':'10.44.0.128/25','dev':'ens3'}],'ens3') is None


def test_openstack_multinic_public_interface_and_source_routing_guard(monkeypatch):
    """Reproduces real OpenStack 2-NIC topology where private NIC ens4 has lower-metric default (200)
    than public NIC ens3 (1002). public_interface() must pick ens3, and ensure_public_routing() must
    install table 188 source-policy routing + higher-priority proto 188 default on ens3 without deleting DHCP routes.
    """
    import subprocess
    routes = [
        {'dst': 'default', 'gateway': '172.16.50.1', 'dev': 'ens4', 'metric': 200},
        {'dst': 'default', 'gateway': '38.47.85.254', 'dev': 'ens3', 'protocol': 'dhcp', 'prefsrc': '38.47.85.185', 'metric': 1002},
        {'dst': '38.47.85.0/24', 'dev': 'ens3', 'protocol': 'dhcp', 'scope': 'link', 'prefsrc': '38.47.85.185', 'metric': 1002},
        {'dst': '172.16.50.0/24', 'dev': 'ens4', 'protocol': 'kernel', 'scope': 'link', 'prefsrc': '172.16.50.240'},
    ]
    # Even without VPNAAS_PUBLIC_IF env var, ens3 wins because 38.47.85.185/254 is globally routable!
    monkeypatch.delenv('VPNAAS_PUBLIC_IF', raising=False)
    assert network.public_interface(routes) == 'ens3'
    assert network.private_route('172.16.50.0/24', routes, 'ens3') == 'ens4'

    # With VPNAAS_PUBLIC_IF explicitly set, it also pins ens3 even on RFC1918 NAT public NICs
    monkeypatch.setenv('VPNAAS_PUBLIC_IF', 'ens3')
    nat_routes = [
        {'dst': 'default', 'gateway': '172.16.50.1', 'dev': 'ens4', 'metric': 200},
        {'dst': 'default', 'gateway': '10.0.0.1', 'dev': 'ens3', 'prefsrc': '10.0.0.10', 'metric': 1002},
    ]
    assert network.public_interface(nat_routes) == 'ens3'

    # Verify ensure_public_routing() installs table 188 + ip rule pref 250 + main proto 188 default metric 190
    monkeypatch.delenv('VPNAAS_DRY_RUN', raising=False)
    monkeypatch.setenv('VPNAAS_PUBLIC_IP', '38.47.85.185')
    monkeypatch.setattr(network, '_interface_ipv4s', lambda dev: ['38.47.85.185'] if dev == 'ens3' else ['172.16.50.240'])
    monkeypatch.setattr(network, '_ip_rules', lambda: [{'priority': 0, 'table': 'local'}, {'priority': 220, 'table': '220'}, {'priority': 32766, 'table': 'main'}])
    calls = []
    monkeypatch.setattr(subprocess, 'run', lambda args, **kw: calls.append(args))

    res = network.ensure_public_routing(routes=routes)
    assert res['changed'] is True
    assert res['public_if'] == 'ens3'
    assert res['public_src'] == '38.47.85.185'
    assert res['override_metric'] == 190
    assert ['ip', '-4', 'route', 'replace', '38.47.85.0/24', 'dev', 'ens3', 'scope', 'link', 'src', '38.47.85.185', 'table', '188', 'proto', '188'] in calls
    assert ['ip', '-4', 'route', 'replace', 'default', 'via', '38.47.85.254', 'dev', 'ens3', 'src', '38.47.85.185', 'table', '188', 'proto', '188'] in calls
    assert ['ip', '-4', 'rule', 'add', 'from', '38.47.85.185/32', 'lookup', '188', 'pref', '250'] in calls
    assert ['ip', '-4', 'route', 'replace', 'default', 'via', '38.47.85.254', 'dev', 'ens3', 'src', '38.47.85.185', 'metric', '190', 'proto', '188'] in calls
    # Never deletes OpenStack/DHCP routes!
    assert not any('del' in a and '172.16.50.1' in a for a in calls)
    monkeypatch.setenv('VPNAAS_DRY_RUN', '1')
