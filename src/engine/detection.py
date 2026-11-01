from typing import Any, Dict, List, Optional

from src.models.detection import Detection
from src.models.engine_types import FlowContext
from src.models.rule import Rule
from src.rules.validator import DEFAULT_PRIORITY


def make_detection(rule: Rule, event: Any, ctx: Optional[FlowContext],
                   matches: List[Dict[str, Any]]) -> Detection:
    """
    Build the Detection Event for `rule` matching `event`. Pure: it prints nothing, writes no file
    and reads no clock (the timestamp is the event's); writing the log is the pipeline's job.

    Rule identity: sid, rev, msg, classtype (None when the rule has none) and priority come from the
    rule. Rules from the Parser always carry a priority; a hand-built rule without one gets
    DEFAULT_PRIORITY (the single constant the Parser also falls back on).
    Packet: timestamp = event.timestamp, packet_id, the 5-tuple from the event, protocol =
    event.transport_protocol (upper case), application_protocol = event.app_protocol (may be None or
    "UNKNOWN").
    Flow: flow_id comes from the context (or from the event when there is no context);
    flow_direction = ctx.role ('to_server' / 'to_client'), the role of the sender, not the
    forward/backward direction, and None when there is no context.
    matched = `matches` (MatchResult.matches); an empty list becomes [{"keyword": "header"}]. Detection
    copies the list and each dict in it, so Detections never share match details.

    Raises ValueError (from Detection) if the event is not TCP/UDP, and AttributeError if the event
    lacks timestamp, packet_id or the 5-tuple. The engine only evaluates proper events, and its
    detect() runs this inside the per-rule guard, so an error here is counted as a rule error.
    """
    priority = rule.priority if rule.priority is not None else DEFAULT_PRIORITY
    protocol = getattr(event, "transport_protocol", None)
    return Detection(
        sid=rule.sid,
        rev=rule.rev,
        msg=rule.msg,
        priority=priority,
        classtype=rule.classtype,
        timestamp=event.timestamp,
        packet_id=event.packet_id,
        src_ip=event.src_ip,
        src_port=event.src_port,
        dst_ip=event.dst_ip,
        dst_port=event.dst_port,
        protocol=protocol.upper() if isinstance(protocol, str) else protocol,
        application_protocol=getattr(event, "app_protocol", None),
        flow_id=ctx.flow_id if ctx is not None else getattr(event, "flow_id", None),
        flow_direction=ctx.role if ctx is not None else None,
        matched=matches or [],
    )
