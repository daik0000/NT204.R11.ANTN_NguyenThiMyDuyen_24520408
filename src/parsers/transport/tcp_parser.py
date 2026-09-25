from typing import Dict, Any, List
from scapy.layers.inet import TCP
from scapy.packet import NoPayload
from src.utils.safe import safe_parse

# Minimum length of a standard TCP header (without options)
MIN_TCP_HEADER_LEN = 20

# Mapping Scapy's 1-letter flag abbreviations to readable standard names
TCP_FLAG_MAP = {
    'F': 'FIN',
    'S': 'SYN',
    'R': 'RST',
    'P': 'PSH',
    'A': 'ACK',
    'U': 'URG',
    'E': 'ECE',
    'C': 'CWR'
}

def decode_tcp_flags(flag_obj: Any) -> List[str]:
    """
    Converts Scapy's TCP flag representation (e.g., 'SA' or '') 
    into a clear, readable list of strings: ['SYN', 'ACK'].
    """
    flag_str = str(flag_obj)
    return [TCP_FLAG_MAP[char] for char in flag_str if char in TCP_FLAG_MAP]

@safe_parse
def parse_tcp(raw_bytes: bytes) -> Dict[str, Any]:
    """
    Decodes the L4 transport payload into a TCP normalized dictionary.
    Extracts critical state-tracking fields (seq, ack, flags) needed for 
    detecting port scans, SYN floods, and TCP handshake anomalies.
    """
    # Defensive programming: Prevent Scapy from silently hallucinating fields 
    # (e.g., src_port=0) when fed a severely truncated TCP segment.
    if len(raw_bytes) < MIN_TCP_HEADER_LEN:
        raise ValueError(
            f"Payload too short to be a valid TCP header "
            f"({len(raw_bytes)} bytes, minimum required is {MIN_TCP_HEADER_LEN})."
        )

    pkt = TCP(raw_bytes)
    tcp_layer = pkt[TCP]
    
    # Safely extract L7 Application payload, handling the NoPayload edge case
    if isinstance(tcp_layer.payload, NoPayload):
        app_payload = b""
    else:
        app_payload = tcp_layer.payload.original
        
    return {
        "status": "OK",
        "transport_protocol": "TCP",
        "src_port": tcp_layer.sport,
        "dst_port": tcp_layer.dport,
        
        # TCP-specific fields grouped for deep stateful analysis
        "transport_fields": {
            "seq": tcp_layer.seq,
            "ack": tcp_layer.ack,
            "flags": decode_tcp_flags(tcp_layer.flags),
            "window_size": tcp_layer.window,
        },
        
        # Raw bytes ready for the Application layer parser (HTTP, DNS, etc.)
        "app_payload": app_payload
    }

if __name__ == "__main__":
    import logging
    import pprint
    
    logging.basicConfig(level=logging.DEBUG)
    print("=== TEST TCP PARSER ===")
    
    # Test 1: Valid TCP packet
    print("\n--- Valid Packet ---")
    dummy_tcp = TCP(sport=443, dport=54321, seq=1000, ack=2000, flags="SA") / b"Hello HTTP"
    pprint.pprint(parse_tcp(bytes(dummy_tcp)))
    
    # Test 2: Truncated Malformed Packet (Simulating the 20-byte length check)
    print("\n--- Truncated Packet ---")
    # Taking only the first 10 bytes of a valid TCP header
    truncated_bytes = bytes(dummy_tcp)[:10]
    pprint.pprint(parse_tcp(truncated_bytes))