from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Literal, Optional

DetectionProtocol = Literal["TCP", "UDP"]
DETECTION_PROTOCOLS = ("TCP", "UDP")

FlowDirectionRole = Literal["to_server", "to_client"]
FLOW_DIRECTION_ROLES = ("to_server", "to_client")

MATCH_KEYWORDS = ("header", "content")


def _is_int(v: Any) -> bool:
    return isinstance(v, int) and not isinstance(v, bool)


def _check_content_match(m: Dict[str, Any]) -> None:
    ok = (isinstance(m.get("value"), str)
          and _is_int(m.get("offset")) and m["offset"] >= 0
          and _is_int(m.get("length")) and m["length"] >= 1)
    if not ok:
        raise ValueError(f"content match needs value (str), offset (int >= 0), length (int >= 1): {m!r}")


@dataclass(kw_only=True)
class Detection:
    """
    One rule match on one packet (one line of detections.jsonl).

    Flat shared fields plus one nested object (`matched`), in the style of Suricata's eve.json.

    # --- Rule identity ---
    sid, rev, msg: copied from the rule.
    priority: the rule's priority, or engine.default_priority when the rule has none (never None).
    classtype: the rule's classtype, None when the rule has none.

    # --- Time / packet (back-references into events.jsonl / flows.jsonl) ---
    timestamp: event.timestamp (epoch seconds). packet_id: event.packet_id.

    # --- 5-tuple ---
    src_ip, src_port, dst_ip, dst_port: as in the event (packet direction, not flow A/B).
    protocol: 'TCP' | 'UDP' (DETECTION_PROTOCOLS).

    # --- Context ---
    application_protocol: event.app_protocol (may be None or "UNKNOWN").
    flow_id: id of the flow the packet belongs to; None when it has no flow.
    flow_direction: ROLE of the packet's sender: 'to_server' | 'to_client' | None
                    (FLOW_DIRECTION_ROLES). Not the forward/backward direction of the Flow.

    # --- Match details ---
    matched: always a non-empty list of dicts, never None. Each element is
        {"keyword": "content", "value": <text>, "offset": <int>, "length": <int>}
        for a content match (offset: byte offset of the match in the payload), or
        {"keyword": "header"} for a rule without content. An empty or None list given
        to the constructor is replaced by [{"keyword": "header"}]. keyword is one of
        MATCH_KEYWORDS. A content element must have value (str), offset (int >= 0) and
        length (int >= 1). The constructor copies the list and its dicts, so Detections
        built from the same event never share a list.

    Validation scope: only what this schema defines is checked (protocol, flow_direction,
    matched). sid, priority, ports and the like come from rules and events that were already
    validated upstream, so they are not re-checked here.

    Mutable on purpose (like IDSEvent and Flow): __post_init__ normalises `matched`.
    """

    # --- Rule identity ---
    sid: int
    rev: int
    msg: str
    priority: int
    classtype: Optional[str] = None

    # --- Time / packet ---
    timestamp: float
    packet_id: int

    # --- 5-tuple ---
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    protocol: DetectionProtocol

    # --- Context ---
    application_protocol: Optional[str] = None
    flow_id: Optional[str] = None
    flow_direction: Optional[FlowDirectionRole] = None

    # --- Match details ---
    matched: List[Dict[str, Any]] = field(default_factory=list)

    def __post_init__(self) -> None:
        if self.protocol not in DETECTION_PROTOCOLS:
            raise ValueError(f"invalid protocol: {self.protocol!r}")
        if self.flow_direction is not None and self.flow_direction not in FLOW_DIRECTION_ROLES:
            raise ValueError(f"invalid flow_direction: {self.flow_direction!r}")
        if not self.matched:
            self.matched = [{"keyword": "header"}]
        else:
            self.matched = [dict(m) if isinstance(m, dict) else m for m in self.matched]
        for m in self.matched:
            if not isinstance(m, dict) or m.get("keyword") not in MATCH_KEYWORDS:
                raise ValueError(f"invalid matched element: {m!r}")
            if m["keyword"] == "content":
                _check_content_match(m)

    def to_dict(self) -> Dict[str, Any]:
        """Dictionary for JSON logging (deep copy: the caller cannot mutate this object)."""
        return asdict(self)
