def test_tuning_settings_and_inert_presets():
    import tuning
    values=tuning.settings()
    assert values['net.ipv4.conf.all.rp_filter']=='2'
    assert values['net.ipv6.conf.default.accept_ra']=='2'
    assert values['net.netfilter.nf_conntrack_max']=='262144'
    assert values['net.ipv4.tcp_rmem']=='4096 87380 16777216'
    assert tuning.PRESETS=={'wireguard_mtu':1360,'openvpn_tun_mtu':1360,'openvpn_mssfix':1320,'active':False}


def test_mss_only_lowers_ipsec_syn_both_directions(monkeypatch):
    from vpn import firewall
    monkeypatch.delenv('VPNAAS_ROUTE_AUTO',raising=False)
    u=dict(id=999999,virtual_ip='172.31.201.1',enabled=True,allowed_cidrs=['192.0.2.0/24'])
    text=firewall([],[u],[])
    rules=[l for l in text.splitlines() if 'maxseg' in l]
    assert len(rules)==2
    assert all('size > 1300 tcp option maxseg size set 1300' in l for l in rules)
    assert 'meta ipsec exists' in rules[0] and 'rt ipsec exists' in rules[1]
    assert 'priority mangle' in text
    c=dict(id=7,enabled=True,remote_ts='198.51.100.0/24',local_ts='192.0.2.0/24')
    rules=[l for l in firewall([c],[],[]).splitlines() if 'maxseg' in l]
    assert len(rules)==2 and all('size > 1300' in l for l in rules)
    assert all('198.51.100.0/24' in l and '192.0.2.0/24' in l for l in rules)
