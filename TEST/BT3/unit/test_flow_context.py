import pytest

from src.engine.flow_context import build_flow_context
from src.flow.tracker import FlowTracker
from src.models.engine_types import FlowContext
from src.models.event import IDSEvent

CFG = {"ports": {80: "HTTP", 53: "DNS", 443: "HTTPS", 25: "SMTP"}}
CLIENT = ("10.0.0.1", 40000)
SERVER = ("10.0.0.2", 80)


def ev(src, dst, flags=("ACK",), proto="TCP", ts=100.0, **kw):
    d = dict(packet_id=1, timestamp=ts, src_ip=src[0], src_port=src[1], dst_ip=dst[0], dst_port=dst[1],
             network_protocol="IPv4", transport_protocol=proto, raw_length=60, preprocess_status="valid",
             payload=b"", transport_fields={"flags": list(flags)} if proto == "TCP" else {})
    d.update(kw)
    return IDSEvent(**d)


def step(tracker, event, cfg=CFG):
    """What the engine does: update(), then snapshot(), then build the context."""
    tracker.update(event)
    return build_flow_context(event, tracker.snapshot(event), cfg)


def view(ctx):
    return ctx.role, ctx.established, ctx.state, ctx.direction, ctx.midstream


# --- TCP, SYN first ------------------------------------------------------------------------------

def test_syn_first_handshake_and_data():
    t = FlowTracker({})
    syn = step(t, ev(CLIENT, SERVER, ["SYN"], ts=1.0))
    synack = step(t, ev(SERVER, CLIENT, ["SYN", "ACK"], ts=1.1))
    ack = step(t, ev(CLIENT, SERVER, ["ACK"], ts=1.2))
    reply = step(t, ev(SERVER, CLIENT, ["PSH", "ACK"], ts=1.3))
    assert view(syn) == ("to_server", False, "HANDSHAKE", "forward", False)
    assert view(synack) == ("to_client", False, "HANDSHAKE", "backward", False)
    assert view(ack) == ("to_server", True, "ESTABLISHED", "forward", False)       # final ACK already counts
    assert view(reply) == ("to_client", True, "ESTABLISHED", "backward", False)
    assert syn.flow_id == reply.flow_id and syn.protocol == "TCP"


def test_not_midstream_endpoint_a_is_client_even_if_its_port_is_a_known_service():
    t = FlowTracker({})
    ctx = step(t, ev(("10.0.0.1", 80), ("10.0.0.2", 40000), ["SYN"]))     # SYN sent FROM port 80
    assert ctx.role == "to_server"


# --- TCP, midstream and server-side capture ------------------------------------------------------------

def test_midstream_ack_from_client_uses_ports():
    t = FlowTracker({})
    first = step(t, ev(CLIENT, SERVER, ["ACK"]))
    back = step(t, ev(SERVER, CLIENT, ["ACK"]))
    assert view(first) == ("to_server", True, "ESTABLISHED", "forward", True)
    assert view(back) == ("to_client", True, "ESTABLISHED", "backward", True)


def test_first_captured_packet_is_from_the_server_forward_is_not_to_server():
    t = FlowTracker({})
    first = step(t, ev(SERVER, CLIENT, ["PSH", "ACK"]))        # endpoint_a becomes the SERVER
    second = step(t, ev(CLIENT, SERVER, ["ACK"]))
    assert (first.direction, first.role) == ("forward", "to_client")
    assert (second.direction, second.role) == ("backward", "to_server")


def test_midstream_synack_first():
    t = FlowTracker({})
    ctx = step(t, ev(SERVER, CLIENT, ["SYN", "ACK"]))
    assert view(ctx) == ("to_client", False, "HANDSHAKE", "forward", True)


# --- UDP ------------------------------------------------------------------------------------------------------

def test_udp_query_then_response():
    t = FlowTracker({})
    query = step(t, ev(("10.0.0.1", 5353), ("10.0.0.2", 53), proto="UDP", ts=1.0))
    reply = step(t, ev(("10.0.0.2", 53), ("10.0.0.1", 5353), proto="UDP", ts=1.1))
    again = step(t, ev(("10.0.0.1", 5353), ("10.0.0.2", 53), proto="UDP", ts=1.2))
    assert view(query) == ("to_server", False, "ACTIVE", "forward", False)       # nothing came back yet
    assert view(reply) == ("to_client", True, "ACTIVE", "backward", False)       # this packet counts
    assert view(again) == ("to_server", True, "ACTIVE", "forward", False)


def test_udp_response_captured_first():
    t = FlowTracker({})
    reply = step(t, ev(("10.0.0.2", 53), ("10.0.0.1", 5353), proto="UDP", ts=1.0))   # endpoint_a = server
    query = step(t, ev(("10.0.0.1", 5353), ("10.0.0.2", 53), proto="UDP", ts=1.1))
    assert view(reply) == ("to_client", False, "ACTIVE", "forward", False)
    assert view(query) == ("to_server", True, "ACTIVE", "backward", False)


# --- which endpoint is the server ----------------------------------------------------------------------------------

def _udp_roles(first, second, cfg):
    t = FlowTracker({})
    a = step(t, ev(first, second, proto="UDP", ts=1.0), cfg)
    b = step(t, ev(second, first, proto="UDP", ts=1.1), cfg)
    return a.role, b.role


def test_exactly_one_port_in_ports_decides():
    # the known port (50000) wins even though it is the LARGER one
    cfg = {"ports": {50000: "X"}}
    assert _udp_roles(("10.0.0.1", 50000), ("10.0.0.2", 100), cfg) == ("to_client", "to_server")


def test_neither_port_known_smaller_port_is_server():
    cfg = {"ports": {}}
    # (roles of the first and the second packet; the first packet is sent by the first endpoint)
    assert _udp_roles(("10.0.0.1", 40000), ("10.0.0.2", 7000), cfg) == ("to_server", "to_client")
    assert _udp_roles(("10.0.0.1", 7000), ("10.0.0.2", 40000), cfg) == ("to_client", "to_server")


def test_both_ports_known_smaller_port_is_server():
    assert _udp_roles(("10.0.0.1", 443), ("10.0.0.2", 80), CFG) == ("to_server", "to_client")     # 80 is the server
    assert _udp_roles(("10.0.0.1", 80), ("10.0.0.2", 443), CFG) == ("to_client", "to_server")


def test_equal_ports_endpoint_a_is_client():
    assert _udp_roles(("10.0.0.1", 5000), ("10.0.0.2", 5000), CFG) == ("to_server", "to_client")


@pytest.mark.parametrize("cfg", [None, {}, {"ports": None}, {"ports": []}, {"ports": {"80": "x"}}])
def test_missing_or_odd_ports_config_falls_back_to_smaller_port(cfg):
    assert _udp_roles(("10.0.0.1", 40000), ("10.0.0.2", 80), cfg) == ("to_server", "to_client")


# --- established by state --------------------------------------------------------------------------------------------------

def _tcp_state_ctx(*packets):
    t = FlowTracker({})
    ctx = None
    for i, (src, dst, flags) in enumerate(packets):
        ctx = step(t, ev(src, dst, flags, ts=1.0 + i / 10))
    return ctx


C, S = CLIENT, SERVER
HANDSHAKE = [(C, S, ["SYN"]), (S, C, ["SYN", "ACK"]), (C, S, ["ACK"])]


def test_established_by_state():
    assert _tcp_state_ctx(*HANDSHAKE[:1]).established is False                      # HANDSHAKE
    assert _tcp_state_ctx(*HANDSHAKE).established is True                           # ESTABLISHED
    closing = _tcp_state_ctx(*HANDSHAKE, (C, S, ["FIN", "ACK"]))
    assert (closing.state, closing.established) == ("CLOSING", True)
    closed = _tcp_state_ctx(*HANDSHAKE, (C, S, ["FIN", "ACK"]), (S, C, ["FIN", "ACK"]))
    assert (closed.state, closed.established) == ("CLOSED", True)


def test_reset_is_not_established_even_after_an_established_connection():
    reset = _tcp_state_ctx(*HANDSHAKE, (S, C, ["RST", "ACK"]))
    assert (reset.state, reset.established) == ("RESET", False)           # documented limitation


# --- no flow context ----------------------------------------------------------------------------------------------------------

def test_exported_flow_gives_no_context_and_guesses_nothing():
    t = FlowTracker({})
    udp = ev(("10.0.0.2", 53), ("10.0.0.1", 5353), proto="UDP")
    tcp = ev(S, C, ["ACK"])
    t.update(udp)
    t.update(tcp)
    t.flush()
    for event in (udp, tcp):
        assert t.snapshot(event) is None
        assert build_flow_context(event, None, CFG) is None


@pytest.mark.parametrize("kw", [dict(preprocess_status="invalid"), dict(transport_protocol="ICMP"), dict(src_ip=None)])
def test_untracked_event_gives_none(kw):
    t = FlowTracker({})
    event = ev(C, S, ["SYN"], **kw)
    t.update(event)
    assert build_flow_context(event, t.snapshot(event), CFG) is None


def test_event_without_a_usable_direction_gives_none_when_it_cannot_be_computed():
    t = FlowTracker({})
    event = ev(C, S, ["SYN"])
    t.update(event)
    flow = t.snapshot(event)
    event.direction = None
    event.src_ip = None                      # direction can neither be read nor recomputed
    assert build_flow_context(event, flow, CFG) is None


def test_direction_is_recomputed_from_the_addresses_when_the_event_has_none():
    t = FlowTracker({})
    event = ev(S, C, ["ACK"])
    t.update(event)
    flow = t.snapshot(event)
    event.direction = None
    assert build_flow_context(event, flow, CFG).direction == "forward"


def test_result_is_a_flow_context():
    t = FlowTracker({})
    assert isinstance(step(t, ev(C, S, ["SYN"])), FlowContext)


def test_tcp_flow_with_state_active_gives_none():
    t = FlowTracker({})
    event = ev(C, S, ["SYN"])
    t.update(event)
    flow = t.snapshot(event)
    event.flow_state = "ACTIVE"
    assert build_flow_context(event, flow, CFG) is None


# --- the two directions always get opposite roles --------------------------------------------------------------------------------

PAIRS = [
    (("10.0.0.1", 40000), ("10.0.0.2", 80), "TCP", ["SYN"]),          # SYN first
    (("10.0.0.2", 80), ("10.0.0.1", 40000), "TCP", ["ACK"]),          # server side first, midstream
    (("10.0.0.1", 40000), ("10.0.0.2", 80), "TCP", ["ACK"]),          # client side first, midstream
    (("10.0.0.1", 52133), ("10.0.0.2", 60000), "TCP", ["ACK"]),       # both ephemeral, midstream
    (("10.0.0.1", 5000), ("10.0.0.2", 5000), "UDP", []),              # equal ports
    (("10.0.0.1", 443), ("10.0.0.2", 80), "UDP", []),                 # both known
    (("10.0.0.1", 9000), ("10.0.0.2", 9001), "UDP", []),              # neither known
]


@pytest.mark.parametrize("a, b, proto, flags", PAIRS)
def test_opposite_directions_get_opposite_roles(a, b, proto, flags):
    t = FlowTracker({})
    first = step(t, ev(a, b, flags, proto=proto, ts=1.0))
    second = step(t, ev(b, a, flags, proto=proto, ts=1.1))
    assert {first.role, second.role} == {"to_server", "to_client"}
    assert (first.direction, second.direction) == ("forward", "backward")


@pytest.mark.parametrize("cfg", [None, {}, CFG, {"ports": {40000: "x", 80: "y"}}])
def test_roles_are_opposite_for_any_ports_config(cfg):
    t = FlowTracker({})
    first = step(t, ev(CLIENT, SERVER, ["ACK"], ts=1.0), cfg)
    second = step(t, ev(SERVER, CLIENT, ["ACK"], ts=1.1), cfg)
    assert first.role != second.role


def test_boolean_keys_in_ports_are_ignored():
    # True == 1: if the key counted as port 1, both ports (1 and 80) would be "known" and the smaller
    # port (1) would be the server, giving the opposite roles. Ignored, only 80 is known -> B is the server.
    cfg = {"ports": {80: "http", True: "x"}}
    assert _udp_roles(("10.0.0.1", 1), ("10.0.0.2", 80), cfg) == ("to_server", "to_client")
