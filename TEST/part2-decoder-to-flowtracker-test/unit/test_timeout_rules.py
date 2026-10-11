import pytest
from src.models.flow import Flow
from src.flow.flow_table import FlowEntry
from src.flow.timeout import timeout_for, is_expired, get_close_reason

SECTION = {"udp_idle_timeout_sec": 60, "tcp_handshake_timeout_sec": 30,
           "tcp_closed_linger_sec": 10, "tcp_idle_timeout_sec": 300}


def entry(proto="TCP", state="ESTABLISHED", start=100.0, last=100.0):
    f = Flow(flow_id="x", protocol=proto, endpoint_a={"ip": "1.1.1.1", "port": 1},
             endpoint_b={"ip": "2.2.2.2", "port": 2}, start_time=start, last_seen=last, state=state)
    return FlowEntry(f)


@pytest.mark.parametrize("proto,state,expected", [
    ("UDP", "ACTIVE", 60), ("TCP", "HANDSHAKE", 30), ("TCP", "CLOSED", 10),
    ("TCP", "RESET", 10), ("TCP", "ESTABLISHED", 300), ("TCP", "CLOSING", 300),
])
def test_timeout_by_type_and_state(proto, state, expected):
    assert timeout_for(entry(proto, state), SECTION) == expected


@pytest.mark.parametrize("proto,state,expected", [
    ("UDP", "ACTIVE", 60), ("TCP", "HANDSHAKE", 30), ("TCP", "CLOSED", 10), ("TCP", "ESTABLISHED", 300),
])
def test_defaults_match_settings_yaml_when_section_empty(proto, state, expected):
    assert timeout_for(entry(proto, state), {}) == expected


def test_whole_config_passed_by_mistake_falls_back_to_defaults_not_crash():
    whole = {"flow": {"udp_idle_timeout_sec": 5}}
    assert timeout_for(entry("UDP", "ACTIVE"), whole) == 60   # contract: pass cfg["flow"]


@pytest.mark.parametrize("bad", ["abc", None, -5, 0, float("nan"), float("inf"), True, [], {}])
def test_invalid_timeout_value_does_not_raise_and_uses_default(bad):
    assert timeout_for(entry("UDP", "ACTIVE"), {"udp_idle_timeout_sec": bad}) == 60


@pytest.mark.parametrize("cfg", [None, 5, "x", []])
def test_non_dict_section_uses_defaults(cfg):
    assert timeout_for(entry("UDP", "ACTIVE"), cfg) == 60


def test_expiry_boundary_is_strictly_greater():
    e = entry("UDP", "ACTIVE", last=100.0)
    assert is_expired(e, 160.0, SECTION) is False   # equal to timeout: still alive
    assert is_expired(e, 160.001, SECTION) is True


def test_not_expired_when_clock_behind_last_seen():
    assert is_expired(entry("UDP", "ACTIVE", last=100.0), 90.0, SECTION) is False


def test_expiry_uses_state_specific_timeout():
    e = entry("TCP", "HANDSHAKE", last=100.0)
    assert is_expired(e, 131.0, SECTION) is True
    e.flow.state = "ESTABLISHED"
    assert is_expired(e, 131.0, SECTION) is False


@pytest.mark.parametrize("state,reason", [
    ("CLOSED", "tcp_closed"), ("RESET", "tcp_reset"), ("HANDSHAKE", "handshake_timeout"),
    ("ESTABLISHED", "idle_timeout"), ("CLOSING", "idle_timeout"), ("ACTIVE", "idle_timeout"),
])
def test_close_reason(state, reason):
    assert get_close_reason(entry("TCP", state)) == reason


def test_duration_excludes_idle_wait():
    e = entry("UDP", "ACTIVE", start=100.0, last=103.0)
    assert is_expired(e, 500.0, SECTION)
    assert e.flow.duration == 3.0