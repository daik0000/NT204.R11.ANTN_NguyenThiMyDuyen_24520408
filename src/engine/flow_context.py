from typing import Any, Dict, Optional

from src.flow.flow_key import direction_of
from src.models.engine_types import CONTEXT_DIRECTIONS, CONTEXT_STATES, FlowContext
from src.models.flow import Flow

# TCP states after the current packet that count as "established" for `flow:established`.
# HANDSHAKE and RESET do not (a RST after an established connection therefore reads as
# not_established; Snort would keep it established - a known, accepted limitation).
ESTABLISHED_TCP_STATES = ("ESTABLISHED", "CLOSING", "CLOSED")


def _known_ports(cfg: Optional[Dict[str, Any]]) -> frozenset:
    ports = cfg.get("ports") if isinstance(cfg, dict) else None
    return frozenset(p for p in ports if isinstance(p, int) and not isinstance(p, bool)) if isinstance(ports, dict) else frozenset()


def _server_index(port_a: int, port_b: int, known: frozenset) -> Optional[int]:
    """
    Which of two endpoints (0 = first, 1 = second) is the server judging by ports alone, or None
    when it cannot be told: exactly one port in `known` -> that one; otherwise the smaller port;
    equal ports -> None.
    """
    a_known, b_known = port_a in known, port_b in known
    if a_known != b_known:
        return 0 if a_known else 1
    if port_a != port_b:
        return 0 if port_a < port_b else 1
    return None


def _packet_direction(event: Any, flow: Flow) -> Optional[str]:
    direction = getattr(event, "direction", None)
    if direction in CONTEXT_DIRECTIONS:
        return direction
    src_ip, src_port = getattr(event, "src_ip", None), getattr(event, "src_port", None)
    if src_ip is None or src_port is None:
        return None
    return direction_of(flow.endpoint_a, src_ip, src_port)


def build_flow_context(event: Any, flow: Optional[Flow],
                       cfg: Optional[Dict[str, Any]] = None) -> Optional[FlowContext]:
    """
    Describe the flow of the packet being tested, for the flow-aware parts of the engine.

    `flow` is FlowTracker.snapshot(event), which MUST be taken after update(event): the context
    then describes the state after the current packet, so the ACK that completes a handshake
    already reads as established. `cfg` is the full config; only cfg["ports"] is read.

    Client and server of the flow:
    - TCP and not midstream: endpoint_a (the sender of the SYN) is the client.
    - otherwise (TCP midstream, UDP): if exactly one endpoint's port is in cfg["ports"] that
      endpoint is the server; if not, the endpoint with the smaller port is the server; equal
      ports -> endpoint_a is the client.
    role is the role of THIS packet's sender: from the client -> 'to_server', else 'to_client'.
    It is NOT the same as direction: 'forward' only means "sent by endpoint_a", and endpoint_a is
    the server when the first packet captured was a response.

    established:
    - TCP: event.flow_state is ESTABLISHED, CLOSING or CLOSED. HANDSHAKE and RESET are not.
    - UDP: the flow has seen a packet in the reverse direction, this one included
      (flow.bwd_packet_count > 0).

    Returns None when there is no flow context: `flow` is None (the event is not tracked, or its
    flow was already exported, e.g. a late packet made the sweep expire it), or the event has no
    usable direction. Nothing is guessed from the event alone, because a wrong guess (for
    example established=False for a UDP response) would make `flow:not_established` rules fire
    by mistake. The caller treats every rule with a `flow:` option as not matching when the
    context is None; rules without `flow:` are unaffected.
    """
    if flow is None:
        return None
    return _from_flow(event, flow, _known_ports(cfg))


def _from_flow(event: Any, flow: Flow, known: frozenset) -> Optional[FlowContext]:
    direction = _packet_direction(event, flow)
    if direction is None:
        return None

    a_port, b_port = flow.endpoint_a["port"], flow.endpoint_b["port"]
    if flow.protocol == "TCP" and not flow.midstream:
        client_is_a = True
    else:
        server = _server_index(a_port, b_port, known)
        client_is_a = server != 0                    # server is A only when told so; tie -> A is client
    sender_is_a = direction == "forward"
    role = "to_server" if sender_is_a == client_is_a else "to_client"

    if flow.protocol == "TCP":
        state = getattr(event, "flow_state", None) or flow.state
        established = state in ESTABLISHED_TCP_STATES
    else:
        state = "ACTIVE"
        established = flow.bwd_packet_count > 0
    if state not in CONTEXT_STATES or (flow.protocol == "TCP" and state == "ACTIVE"):
        return None
    return FlowContext(flow_id=flow.flow_id, protocol=flow.protocol, state=state, role=role,
                       established=established, midstream=bool(flow.midstream), direction=direction)
