import dataclasses
from dataclasses import dataclass, field
from typing import Dict, Optional, Any, Literal

# Defining sets of values ​​helps the type checker and IDE catch errors
Status = Literal["OK", "UNKNOWN", "MALFORMED"]
DetectionMethod = Literal["port", "payload", "port+payload"]
NetworkProtocol = Literal["IPv4", "IPv6"]
TransportProtocol = Literal["TCP", "UDP", "ICMP"]

@dataclass
class IDSEvent:
    """
    Defining the structure for a single network event (Normalized IDS Event).
    All Parser modules (Network, Transport, Application) must adhere to this schema before the data is pushed to the JSONL Logger.
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

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert the IDSEvent dataclass instance to a dictionary.
        """
        return dataclasses.asdict(self)