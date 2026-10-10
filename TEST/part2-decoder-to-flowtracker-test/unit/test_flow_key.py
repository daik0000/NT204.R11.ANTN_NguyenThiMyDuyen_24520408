from src.flow.flow_key import make_key, direction_of

A = ("10.0.0.1", 40000)
B = ("10.0.0.2", 80)


def test_key_is_the_same_in_both_directions():
    assert make_key("TCP", *A, *B) == make_key("TCP", *B, *A)


def test_key_orders_endpoints_and_uppercases_protocol():
    assert make_key("tcp", *B, *A) == ("TCP", A, B)


def test_protocol_is_part_of_the_key():
    assert make_key("TCP", *A, *B) != make_key("UDP", *A, *B)


def test_different_ports_or_ips_are_distinct_flows():
    assert make_key("TCP", "10.0.0.1", 1, "10.0.0.2", 80) != make_key("TCP", "10.0.0.1", 2, "10.0.0.2", 80)
    assert make_key("TCP", "10.0.0.1", 1, "10.0.0.2", 80) != make_key("TCP", "10.0.0.1", 1, "10.0.0.3", 80)


def test_missing_protocol_falls_back_without_raising():
    assert make_key(None, *A, *B)[0] == "UNKNOWN"


def test_same_ip_orders_by_numeric_port():
    assert make_key("UDP", "10.0.0.1", 9, "10.0.0.1", 10)[1:] == (("10.0.0.1", 9), ("10.0.0.1", 10))


def test_self_connection_does_not_raise():
    assert make_key("TCP", *A, *A) == ("TCP", A, A)


def test_direction_is_relative_to_endpoint_a():
    ep_a = {"ip": A[0], "port": A[1]}
    assert direction_of(ep_a, *A) == "forward"
    assert direction_of(ep_a, *B) == "backward"
    assert direction_of(ep_a, A[0], 12345) == "backward"   # same IP, different port
    assert direction_of(ep_a, B[0], A[1]) == "backward"    # same port, different IP


def test_direction_for_self_connection_is_forward():
    assert direction_of({"ip": A[0], "port": A[1]}, *A) == "forward"