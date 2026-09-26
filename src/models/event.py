import dataclasses
from dataclasses import dataclass, field
from typing import Dict, Optional, Any, Literal

# Defining sets of values ​​helps the type checker and IDE catch errors
Status = Literal["OK", "UNKNOWN", "MALFORMED", "IGNORED"]
DetectionMethod = Literal["port", "payload", "port+payload"]
NetworkProtocol = Literal["IPv4", "IPv6"]
TransportProtocol = Literal["TCP", "UDP", "ICMP"]

@dataclass
class IDSEvent:
    """
    Normalized IDS Event Schema.
    status: Literal["OK", "UNKNOWN", "MALFORMED", "IGNORED"]
    - OK: Parsed successfully
    - UNKNOWN: Packet is outside the processing scope (e.g., ARP, IPv6 at the Network layer)
    - MALFORMED: Structural/format error during parsing
    - IGNORED: Packet intentionally skipped based on system configuration (e.g., skip policy)
    """
    
    # Layer 2 - Data Link Layer
    packet_id: int
    timestamp: float
    
    # Layer 3 - Network Layer
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    network_protocol: Optional[NetworkProtocol] = None
    network_fields: Dict[str, Any] = field(default_factory=dict)
    
    # Layer 4 - Transport Layer
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    transport_protocol: Optional[TransportProtocol] = None
    transport_fields: Dict[str, Any] = field(default_factory=dict)
    
    # Layer 7 - Application Layer
    app_protocol: str = "UNKNOWN"
    detection_method: Optional[DetectionMethod] = None
    app_fields: Dict[str, Any] = field(default_factory=dict)
    
    # Metadata and parser information
    raw_length: int = 0
    payload_length: int = 0
    status: Status = "OK"
    
    # Optional error information for malformed packets or parsing issues
    error_info: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert the IDSEvent dataclass instance to a dictionary.
        """
        return dataclasses.asdict(self)