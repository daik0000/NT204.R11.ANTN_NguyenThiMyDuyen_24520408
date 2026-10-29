import ipaddress
from typing import Any, Callable, Dict, List, Optional

from src.flow.tcp_state import normalize_flags
from src.models.engine_types import FAILED_STAGES, FlowContext, MatchResult
from src.models.rule import DsizeSpec, FlagsSpec, IpSpec, PortSpec, Rule


def _ip_to_int(value: Any) -> Optional[int]:
    """IPv4 address text as an integer, or None if it is not a valid IPv4 address string."""
    if not isinstance(value, str):
        return None
    try:
        return int(ipaddress.IPv4Address(value))
    except ValueError:
        return None


def _ip_in(spec: IpSpec, ip: int) -> bool:
    return spec.any or (ip & spec.mask) == spec.network


def _port_in(spec: PortSpec, port: int) -> bool:
    return spec.lo <= port <= spec.hi


def _valid_port(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= 65535


def match_header(rule: Rule, event: Any) -> bool:
    """
    Does the packet fit the rule header (protocol, addresses, ports, direction)? Never raises.

    - protocol: a 'tcp' or 'udp' rule needs the same transport protocol; an 'ip' rule accepts any
      TCP or UDP packet. An event with another or no transport protocol never matches.
    - '->': the packet's source must fit the rule's source (IP and port) and its destination the
      rule's destination.
    - '<>': the forward test above, or the reversed one. Reversed means the packet's source is
      compared with the rule's DESTINATION and the packet's destination with the rule's SOURCE,
      IP and port together; the two sides are never mixed (a packet with the rule's source IP but
      the rule's destination port matches neither way).
    - An event whose IPs are not valid IPv4 strings, or whose ports are not ints in 0..65535, does
      not match (False), it does not raise, not even for an 'any any' rule: corrupt data never matches.
      Each IP is converted to an integer once per call (so once per rule tested, see the README).

    Only the header is checked; flags, flow, dsize and content are other stages.
    """
    protocol = getattr(event, "transport_protocol", None)
    protocol = protocol.lower() if isinstance(protocol, str) else None
    if protocol not in ("tcp", "udp"):
        return False
    if rule.protocol != "ip" and rule.protocol != protocol:
        return False

    src_port, dst_port = getattr(event, "src_port", None), getattr(event, "dst_port", None)
    if not (_valid_port(src_port) and _valid_port(dst_port)):
        return False
    src_ip, dst_ip = _ip_to_int(getattr(event, "src_ip", None)), _ip_to_int(getattr(event, "dst_ip", None))
    if src_ip is None or dst_ip is None:
        return False

    if (_ip_in(rule.src_ip, src_ip) and _port_in(rule.src_port, src_port)
            and _ip_in(rule.dst_ip, dst_ip) and _port_in(rule.dst_port, dst_port)):
        return True
    if rule.direction == "<>":
        return (_ip_in(rule.dst_ip, src_ip) and _port_in(rule.dst_port, src_port)
                and _ip_in(rule.src_ip, dst_ip) and _port_in(rule.src_port, dst_port))
    return False


def match_flow(rule: Rule, ctx: Optional[FlowContext]) -> bool:
    """
    Does the flow context satisfy the rule's `flow:` option? Never raises.

    - The rule has no flow option: True, whatever ctx is (even None).
    - The rule has one but there is no context (ctx is None): False; nothing is guessed.
    - role ('to_server' / 'to_client'), if the rule asks for one: ctx.role must be equal.
      build_flow_context always sets a role today; a None role (defensive branch, for a context
      built by hand or by a future change) matches no rule that names a role.
    - state, if the rule asks for one: 'established' needs ctx.established True, 'not_established'
      needs it False. ctx.established is the state AFTER the current packet (see
      build_flow_context), so the first SYN is not established and the ACK that completes the
      handshake already is.
    """
    flow = rule.flow
    if flow is None:
        return True
    if ctx is None:
        return False
    if flow.role is not None and ctx.role != flow.role:      # a None role never equals a real one
        return False
    if flow.state == "established" and not ctx.established:
        return False
    if flow.state == "not_established" and ctx.established:
        return False
    return True


# Event flag names (as stored by the TCP parser) -> the letters used in rules.
FLAG_LETTERS = {"FIN": "F", "SYN": "S", "RST": "R", "PSH": "P", "ACK": "A",
                "URG": "U", "ECE": "E", "CWR": "C"}


def match_flags(spec: Optional[FlagsSpec], event: Any) -> bool:
    """
    Do the TCP flags of the packet satisfy the rule's `flags:` option? Never raises.

    The event's flag list is normalised with the Part 2 helper (normalize_flags: upper case,
    list/tuple/set only) and turned into rule letters F S R P A U E C. Then, by spec.mode:
      exact  the set of flags equals spec.flags (so flags:A does NOT match PSH/ACK or FIN/ACK;
             flags:0, an empty spec, matches a packet with no flag at all)
      all    spec.flags is a subset of the packet's flags (flags:A+)
      any    the two sets intersect (flags:SF*)
      none   the two sets are disjoint (flags:!S)
    No spec (None) means no constraint: True. A packet that is not TCP, or whose flag list is
    missing or not a list/tuple/set, gives False, since its flags are unknown. A flag name the
    parser does not know is ignored (the Preprocessor already marks a packet with an unknown TCP flag
    invalid, so such a packet does not reach the engine).
    """
    if spec is None:
        return True
    if str(getattr(event, "transport_protocol", "")).upper() != "TCP":
        return False
    fields = getattr(event, "transport_fields", None)
    raw = fields.get("flags") if isinstance(fields, dict) else None
    if not isinstance(raw, (list, tuple, set, frozenset)):
        return False

    present = {FLAG_LETTERS[name] for name in normalize_flags(raw) if name in FLAG_LETTERS}
    wanted = spec.flags
    if spec.mode == "exact":
        return present == wanted
    if spec.mode == "all":
        return wanted <= present
    if spec.mode == "any":
        return bool(wanted & present)
    return not (wanted & present)                   # 'none'


def match_dsize(spec: Optional[DsizeSpec], event: Any) -> bool:
    """
    Does the payload length satisfy the rule's `dsize:` option? Never raises.

    n is len(event.payload), the real bytes (not payload_length, which can disagree); a missing
    or empty payload is 0 bytes. eq: n == a; lt: n < a; gt: n > a; range: a <= n <= b (both ends
    included). It measures one segment or datagram, TCP streams are not reassembled (as in Snort).
    No spec (None) means no constraint: True. A payload that is not bytes-like cannot
    be measured and gives False.
    """
    if spec is None:
        return True
    payload = getattr(event, "payload", None) or b""
    if not isinstance(payload, (bytes, bytearray, memoryview)):
        return False
    n = len(payload)
    if spec.op == "eq":
        return n == spec.a
    if spec.op == "lt":
        return n < spec.a
    if spec.op == "gt":
        return n > spec.a
    return spec.a <= n <= spec.b                    # 'range'


# A content matcher is plugged in by the content stage (B3-7): given the rule and the event it returns
# the list of match details (non-empty, same element format as Detection.matched) or None / [] when
# the rule's contents do not match.
ContentFn = Callable[[Rule, Any], Optional[List[Dict[str, Any]]]]

STAGES = FAILED_STAGES        # one list of stage names, shared with MatchResult.failed_stage


def match_rule(rule: Rule, event: Any, ctx: Optional[FlowContext],
               content_fn: Optional[ContentFn] = None, stats: Any = None) -> MatchResult:
    """
    Test one rule against one packet, stage by stage, cheapest first:

        header -> flow -> packet (flags, dsize) -> content

    The first stage that fails ends the test; its name is MatchResult.failed_stage, so a rule that
    was dropped before the costly content search can be told apart (and counted) from one that
    failed in it. The order is fixed on purpose and must not be rearranged "for speed": cheap
    checks first is what keeps content matching rare.

    - flow: ctx is the FlowContext of the packet (None if there is none); see match_flow.
    - packet: flags and dsize both have to hold.
    - content: skipped for a rule without content; the result then carries
      matches=[{"keyword": "header"}]. For a rule with content, content_fn(rule, event) is called
      only when every earlier stage passed; its non-empty list becomes MatchResult.matches (the list and its dicts are copied), and
      None / [] means the content stage failed. If the rule has content but no content_fn was given
      the content cannot be confirmed, so that stage fails (the engine must therefore always pass
      its content_fn; forgetting it would silently reject every rule that has content).
    - stats: optional counter. For each stage actually evaluated it gets
      stats.record_stage(stage, passed). Stages after a failure are not evaluated, so they are not
      recorded. Note the meaning for counters: the flow stage runs for every rule that reaches it,
      also for rules without a flow: option (which always pass), so "flow stage evaluated" does not
      mean "rule uses flow:"; only the failures (passed=False) say a rule was rejected by flow.
      The content stage is recorded only for rules that have content.

    The matchers do not raise. An exception raised by content_fn is not caught here: the engine
    isolates each rule.
    """
    def record(stage: str, passed: bool) -> None:
        if stats is not None:
            stats.record_stage(stage, passed)

    def fail(stage: str) -> MatchResult:
        return MatchResult(False, rule, failed_stage=stage)

    ok = match_header(rule, event)
    record("header", ok)
    if not ok:
        return fail("header")

    ok = match_flow(rule, ctx)
    record("flow", ok)
    if not ok:
        return fail("flow")

    ok = match_flags(rule.flags, event) and match_dsize(rule.dsize, event)
    record("packet", ok)
    if not ok:
        return fail("packet")

    if not rule.contents:
        return MatchResult(True, rule, matches=[{"keyword": "header"}])

    found = content_fn(rule, event) if content_fn is not None else None
    record("content", bool(found))
    if not found:
        return fail("content")
    return MatchResult(True, rule, matches=[dict(m) for m in found])
