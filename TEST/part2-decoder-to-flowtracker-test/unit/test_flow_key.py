import os
import subprocess
import sys

import pytest

from src.flow.flow_key import make_key, direction_of, make_flow_id

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


KEY = make_key("TCP", "10.0.0.1", 40000, "10.0.0.2", 80)


def test_flow_id_is_16_hex_chars_and_repeatable():
    fid = make_flow_id(KEY, 1700000000.123456)
    assert len(fid) == 16 and int(fid, 16) >= 0
    assert fid == make_flow_id(KEY, 1700000000.123456)


def test_flow_id_has_a_fixed_known_value():
    # Golden value: if this changes, flow_id is no longer reproducible across versions.
    assert make_flow_id(KEY, 1700000000.123456) == "ff9adcff84d66cda"


def test_flow_id_does_not_depend_on_packet_direction():
    k1 = make_key("TCP", "10.0.0.1", 40000, "10.0.0.2", 80)
    k2 = make_key("TCP", "10.0.0.2", 80, "10.0.0.1", 40000)
    assert make_flow_id(k1, 5.0) == make_flow_id(k2, 5.0)


def test_same_five_tuple_at_a_different_time_gets_a_different_id():
    assert make_flow_id(KEY, 5.0) != make_flow_id(KEY, 6.0)
    assert make_flow_id(KEY, 5.000001) != make_flow_id(KEY, 5.000002)   # 1 microsecond apart


def test_sub_microsecond_noise_does_not_change_the_id():
    assert make_flow_id(KEY, 5.0000001) == make_flow_id(KEY, 5.0)


@pytest.mark.parametrize("other", [
    make_key("UDP", "10.0.0.1", 40000, "10.0.0.2", 80),
    make_key("TCP", "10.0.0.1", 40001, "10.0.0.2", 80),
    make_key("TCP", "10.0.0.1", 40000, "10.0.0.3", 80),
])
def test_different_flows_get_different_ids(other):
    assert make_flow_id(KEY, 5.0) != make_flow_id(other, 5.0)


def test_flow_id_is_independent_of_pythonhashseed():
    code = ("from src.flow.flow_key import make_key, make_flow_id;"
            "print(make_flow_id(make_key('TCP','10.0.0.1',40000,'10.0.0.2',80), 1700000000.123456))")
    outs = {subprocess.run([sys.executable, "-c", code], capture_output=True, text=True,
                           env={**os.environ, "PYTHONHASHSEED": seed}).stdout.strip()
            for seed in ("0", "1", "12345")}
    assert len(outs) == 1 and len(next(iter(outs))) == 16


def test_non_finite_start_time_raises_instead_of_producing_a_bogus_id():
    with pytest.raises((ValueError, OverflowError)):
        make_flow_id(KEY, float("nan"))