import pytest

from src.engine.flow_context import build_flow_context
from src.engine.matcher import match_flow
from src.flow.tracker import FlowTracker
from src.models.engine_types import FlowContext
from src.models.event import IDSEvent
from src.rules.validator import parse_rule

CFG = {"ports": {80: "HTTP", 53: "DNS"}}
C = ("10.0.0.1", 40000)
S = ("10.0.0.2", 80)


def rule(flow_option=None):
    option = f" flow:{flow_option};" if flow_option else ""
    result = parse_rule(f'alert tcp any any -> any any (msg:"x";{option} sid:1;)')
    assert result.status == "valid", result
    return result.rule


def ctx(role="to_server", established=True, state=None, protocol="TCP", midstream=False):
    state = state or ("ACTIVE" if protocol == "UDP" else ("ESTABLISHED" if established else "HANDSHAKE"))
    return FlowContext(flow_id="f", protocol=protocol, state=state, role=role, established=established,
                       midstream=midstream, direction="forward")


def pkt(src, dst, flags, ts):
    return IDSEvent(packet_id=1, timestamp=ts, src_ip=src[0], src_port=src[1], dst_ip=dst[0], dst_port=dst[1],
                    network_protocol="IPv4", transport_protocol="TCP", raw_length=60,
                    preprocess_status="valid", payload=b"", transport_fields={"flags": flags})


def context_after(tracker, event):
    tracker.update(event)
    return build_flow_context(event, tracker.snapshot(event), CFG)


# --- hand-computed from real packets --------------------------------------------------------------------

def test_syn_ack_and_data_packets():
    t = FlowTracker({})
    syn = context_after(t, pkt(C, S, ["SYN"], 1.0))                     # HANDSHAKE -> not established
    synack = context_after(t, pkt(S, C, ["SYN", "ACK"], 1.1))
    ack = context_after(t, pkt(C, S, ["ACK"], 1.2))                     # three-way handshake done
    est, not_est = rule("established"), rule("not_established")
    assert (match_flow(est, syn), match_flow(not_est, syn)) == (False, True)
    assert (match_flow(est, synack), match_flow(not_est, synack)) == (False, True)
    assert (match_flow(est, ack), match_flow(not_est, ack)) == (True, False)


def test_first_data_packet_of_a_midstream_flow_is_established():
    t = FlowTracker({})
    data = context_after(t, pkt(C, S, ["PSH", "ACK"], 1.0))
    assert data.midstream is True
    assert match_flow(rule("established"), data) is True
    assert match_flow(rule("to_server,established"), data) is True
    assert match_flow(rule("not_established"), data) is False


def test_role_follows_the_sender_not_the_direction():
    t = FlowTracker({})
    reply = context_after(t, pkt(S, C, ["PSH", "ACK"], 1.0))            # server answers first: forward + to_client
    assert reply.direction == "forward"
    assert match_flow(rule("to_client"), reply) is True
    assert match_flow(rule("to_server"), reply) is False
    assert match_flow(rule("from_server"), reply) is True
    assert match_flow(rule("from_client"), reply) is False


# --- every combination, on hand-built contexts -----------------------------------------------------------------

@pytest.mark.parametrize("option, role, established, expected", [
    (None, "to_server", True, True),
    (None, None, False, True),
    ("to_server", "to_server", True, True),
    ("to_server", "to_server", False, True),
    ("to_server", "to_client", True, False),
    ("to_server", None, True, False),
    ("to_client", "to_client", False, True),
    ("to_client", "to_server", False, False),
    ("to_client", None, False, False),
    ("established", "to_server", True, True),
    ("established", "to_client", True, True),
    ("established", None, True, True),               # no role asked, so an unknown role does not matter
    ("established", "to_server", False, False),
    ("not_established", "to_client", False, True),
    ("not_established", None, False, True),
    ("not_established", "to_server", True, False),
    ("to_server,established", "to_server", True, True),
    ("to_server,established", "to_server", False, False),
    ("to_server,established", "to_client", True, False),
    ("to_server,established", None, True, False),
    ("to_client,not_established", "to_client", False, True),
    ("to_client,not_established", "to_client", True, False),
    ("to_client,not_established", "to_server", False, False),
    ("from_client,established", "to_server", True, True),
    ("from_server,established", "to_server", True, False),
])
def test_combinations(option, role, established, expected):
    assert match_flow(rule(option), ctx(role=role, established=established)) is expected


# --- no context --------------------------------------------------------------------------------------------------------

def test_rule_without_flow_option_ignores_the_context_entirely():
    assert match_flow(rule(None), None) is True


@pytest.mark.parametrize("option", ["to_server", "to_client", "established", "not_established", "to_server,established"])
def test_rule_with_flow_option_never_matches_without_a_context(option):
    assert match_flow(rule(option), None) is False


def test_udp_context():
    # UDP: established means "a reply has been seen"
    assert match_flow(rule("established"), ctx(protocol="UDP", established=True, role="to_client")) is True
    assert match_flow(rule("not_established"), ctx(protocol="UDP", established=False, role="to_server")) is True
    assert match_flow(rule("to_server,established"), ctx(protocol="UDP", established=False, role="to_server")) is False
