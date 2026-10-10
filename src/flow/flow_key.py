from typing import Tuple
import hashlib

def make_key(protocol: str, src_ip: str, src_port: int, dst_ip: str, dst_port: int) -> Tuple[str, Tuple[str, int], Tuple[str, int]]:
    """
    Creates a consistent, directionless routing key for a flow.
    By sorting the endpoints, packets from A->B and B->A will yield the exact same key.
    
    Args:
        protocol: Transport protocol (e.g., "TCP", "UDP").
        src_ip: Normalized source IP.
        src_port: Source port (int).
        dst_ip: Normalized destination IP.
        dst_port: Destination port (int).
        
    Returns:
        A tuple of (protocol, endpoint_small, endpoint_large).
    """
    # Safe fallback if protocol is somehow missing or not string
    proto = str(protocol).upper() if protocol else "UNKNOWN"
    
    ep1 = (src_ip, src_port)
    ep2 = (dst_ip, dst_port)
    
    # Sort endpoints to ensure bidirectional matching.
    # If ep1 == ep2 (loopback edge case), it falls through safely.
    if ep1 <= ep2:
        return (proto, ep1, ep2)
    return (proto, ep2, ep1)


def direction_of(endpoint_a: dict, src_ip: str, src_port: int) -> str:
    """
    Determines the direction of the current packet relative to the established flow.
    
    Args:
        endpoint_a: Dictionary representing the flow initiator (e.g., {"ip": "1.2.3.4", "port": 80}).
        src_ip: Normalized source IP of the current packet.
        src_port: Source port of the current packet.
        
    Returns:
        "forward" if the packet is sent by endpoint_a (the flow initiator), else "backward".
        
    Convention (to be documented in README):
    - endpoint_a: The initiator (the sender of the FIRST packet seen in the flow).
    - "forward": Packet flows A -> B.
    - "backward": Packet flows B -> A.
    
    If src == dst (loopback edge case), this naturally evaluates to "forward".
    """
    if endpoint_a["ip"] == src_ip and endpoint_a["port"] == src_port:
        return "forward"
        
    return "backward"

def make_flow_id(key: Tuple[str, Tuple[str, int], Tuple[str, int]], start_time: float) -> str:
    """
    Generates a deterministic identifier for a flow from its canonical 5-tuple and
    microsecond-precision start time (reproducible across runs, distinct on port reuse).
    """
    proto, ep1, ep2 = key
    ip1, port1 = ep1
    ip2, port2 = ep2

    # Integer microseconds avoid float repr differences across platforms/versions.
    start_us = int(round(start_time * 1_000_000))

    raw_str = f"{proto}|{ip1}:{port1}|{ip2}:{port2}|{start_us}"
    return hashlib.blake2b(raw_str.encode("utf-8"), digest_size=8).hexdigest()