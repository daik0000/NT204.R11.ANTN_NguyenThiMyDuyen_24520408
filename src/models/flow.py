import dataclasses
from dataclasses import dataclass
from typing import Any, Dict, Literal, Optional

FlowProtocol = Literal["TCP", "UDP"]
FlowState = Literal["HANDSHAKE", "ESTABLISHED", "CLOSING", "CLOSED", "RESET", "ACTIVE"]
CloseReason = Literal[
    "tcp_closed", "tcp_reset", "idle_timeout", "handshake_timeout",
    "port_reuse", "evicted", "flush",
]

@dataclass(kw_only=True)
class Flow:
    """
    Flow record - a bidirectional connection/session (Table 5.4 of the assignment).

    endpoint_a: the sender of the first observed packet (usually the initiator, unless midstream).
    state: TCP -> HANDSHAKE | ESTABLISHED | CLOSING | CLOSED | RESET; UDP -> always "ACTIVE".
           Must be provided during flow creation to prevent invalid default states.
    close_reason: None while the flow is active; populated when the flow is exported.
    duration: derived property = max(0, last_seen - start_time), not stored in the object.
    """

    # --- Identifiers ---
    flow_id: str
    protocol: FlowProtocol
    endpoint_a: Dict[str, Any]          # {"ip": str, "port": int}
    endpoint_b: Dict[str, Any]
    application_protocol: Optional[str] = None

    # --- Time (epoch seconds, event-time) ---
    start_time: float
    last_seen: float

    # --- Totals ---
    packet_count: int = 0
    byte_count: int = 0                 # total frame length (matches Wireshark's Bytes column)
    payload_byte_count: int = 0         # application layer data length only

    # --- Directional (forward = A -> B, backward = B -> A) ---
    fwd_packet_count: int = 0
    fwd_byte_count: int = 0
    bwd_packet_count: int = 0
    bwd_byte_count: int = 0

    # --- TCP (count of packets carrying the flag; strictly 0 for UDP) ---
    syn_count: int = 0
    ack_count: int = 0
    fin_count: int = 0
    rst_count: int = 0
    
    state: FlowState
    """
    Current state of the connection flow:
    - UDP: 
      * 'ACTIVE': Stateless protocol.
    - TCP:
      * 'HANDSHAKE': Connection establishment in progress (SYN seen).
      * 'ESTABLISHED': Connection successfully established, transmitting data.
      * 'CLOSING': Connection termination initiated (at least one FIN seen).
      * 'CLOSED': Connection terminated safely (FINs from both sides seen).
      * 'RESET': Connection aborted abruptly (RST seen).
    """

    # --- Auxiliary ---
    close_reason: Optional[CloseReason] = None
    midstream: bool = False             # flow started in the middle (no SYN observed)

    @property
    def duration(self) -> float:
        return max(0.0, self.last_seen - self.start_time)

    def to_dict(self) -> Dict[str, Any]:
        """Dictionary for JSON logging; inserts `duration` immediately after `last_seen`."""
        d: Dict[str, Any] = {}
        for k, v in dataclasses.asdict(self).items():
            d[k] = v
            if k == "last_seen":
                d["duration"] = self.duration
        return d