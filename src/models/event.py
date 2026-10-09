import dataclasses
from dataclasses import dataclass, field
from typing import Any, Dict, List, Literal, Optional

Status = Literal["OK", "UNKNOWN", "MALFORMED", "IGNORED"]
DetectionMethod = Literal["port", "payload", "port+payload"]
DecodeStatus = Literal["OK", "PARTIAL", "FAILED", "SKIPPED"]
PreprocessStatus = Literal["valid", "partial", "invalid"]
ProcessingAction = Literal["none", "normalized", "defaults_filled", "flagged", "skipped", "dropped"]
Direction = Literal["forward", "backward"]


@dataclass
class IDSEvent:
    """
    Normalized IDS Event Schema - Data contract between modules.

    status (Part 1 - Parser): OK | UNKNOWN | MALFORMED | IGNORED
      - IGNORED: packet parsed successfully but intentionally skipped based on unknown_policy;
        error_info is always None.
    app_protocol: None = detector has not run; "UNKNOWN" = run but could not identify.
    error_info: None, or {"layer": ..., "detail": ...} when an actual error occurs.

    decode_status (Part 2 - Decoder): None (not run) | OK | PARTIAL | FAILED | SKIPPED
    preprocess_status (Part 2 - Preprocessor): None (not run) | valid | partial | invalid
    processing_action: None | "none" | "normalized" | "defaults_filled" | "flagged" | "skipped" | "dropped"
    reason: list of short reason codes (e.g., ["missing_src_ip"]); [] when none.
    timestamp_iso: UTC ISO-8601, populated by Preprocessor.
    flow_id / direction / flow_state: populated by Flow Tracker; direction is "forward" | "backward";
      flow_state is the flow state immediately after processing this packet.
    payload: raw application layer bytes, ONLY in-memory - never logged (see to_dict).
    """

    # Identity & time
    packet_id: int
    timestamp: float
    
    # Layer 3 - Network Layer
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    network_protocol: Optional[str] = None
    network_fields: Dict[str, Any] = field(default_factory=dict)
    
    # Layer 4 - Transport Layer
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    transport_protocol: Optional[str] = None
    transport_fields: Dict[str, Any] = field(default_factory=dict)

    # Layer 7 - Application Layer
    app_protocol: Optional[str] = None
    detection_method: Optional[DetectionMethod] = None
    app_fields: Dict[str, Any] = field(default_factory=dict)

    # Metadata
    raw_length: int = 0
    payload_length: int = 0
    status: Status = "OK"
    error_info: Optional[Dict[str, Any]] = None

    # --- Part 2 ---
    decoded_fields: Dict[str, Any] = field(default_factory=dict)
    decode_status: Optional[DecodeStatus] = None

    timestamp_iso: Optional[str] = None
    preprocess_status: Optional[PreprocessStatus] = None
    processing_action: Optional[ProcessingAction] = None
    reason: List[str] = field(default_factory=list)

    flow_id: Optional[str] = None
    direction: Optional[Direction] = None
    flow_state: Optional[str] = None

    payload: Optional[bytes] = field(default=None, repr=False)

    def to_dict(self) -> Dict[str, Any]:
        """Safe dict for JSON logging: removes `payload` (bytes cannot be serialized and shouldn't be logged)."""
        d = dataclasses.asdict(self)
        d.pop("payload", None)
        return d