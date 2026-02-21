from ddos_gateway import AIDDoSGateway


def test_allows_normal_traffic():
    gw = AIDDoSGateway(bucket_capacity=5, bucket_refill_rate=5)
    decision = gw.process_request("1.1.1.1", "/home", now=0.0)
    assert decision.action == "allow"
    assert decision.risk < gw.challenge_threshold


def test_challenges_when_bucket_drained():
    gw = AIDDoSGateway(bucket_capacity=2, bucket_refill_rate=0.0)
    gw.process_request("2.2.2.2", "/home", now=0.0)
    gw.process_request("2.2.2.2", "/home", now=0.0)
    decision = gw.process_request("2.2.2.2", "/home", now=0.0)
    assert decision.action in {"challenge", "block"}


def test_blocks_ip_and_keeps_blocking():
    gw = AIDDoSGateway(bucket_capacity=1, bucket_refill_rate=0.0)
    first = gw.process_request("3.3.3.3", "/login", now=0.0)
    second = gw.process_request("3.3.3.3", "/login", now=0.0)
    if first.action != "block":
        assert second.action == "block"
    third = gw.process_request("3.3.3.3", "/home", now=10.0)
    assert third.action == "block"
    assert third.reason == "ip_blocklisted"
