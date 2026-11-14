import network

def test_late_private_route_requires_specific_safe_route():
    default=[{'dst':'default','dev':'ens3','gateway':'203.0.113.254'}]
    assert network.private_route('10.44.0.0/24',default,'ens3') is None
    attached=default+[{'dst':'10.44.0.0/24','dev':'ens9','prefsrc':'10.44.0.2'}]
    assert network.private_route('10.44.0.0/24',attached,'ens3')=='ens9'
    assert network.private_route('10.44.0.0/16',attached,'ens3') is None
    assert network.private_route('10.44.0.0/24',default+[{'dst':'10.44.0.0/24','dev':'ens3'}],'ens3') is None
    assert network.private_route('10.44.0.0/24',attached+[{'dst':'10.44.0.128/25','dev':'ens3'}],'ens3') is None
