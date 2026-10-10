import time
import math
from typing import Any, Tuple, List, Set

# Valid TCP flags as defined in standards
_VALID_TCP_FLAGS = {"SYN", "ACK", "FIN", "RST", "PSH", "URG", "ECE", "CWR"}

def validate(event: Any, cfg: Any) -> Tuple[str, List[str]]:
    """
    Validates an IDSEvent to determine its data quality level.
    
    Levels (as defined in README):
    - valid: Contains all mandatory fields with strictly valid values.
    - partial: Usable, but some information is missing or degraded (e.g., unsupported 
      protocol, partial/failed decode status, or missing transport layer).
    - invalid: Missing or malformed mandatory fields. Untrustworthy for further processing.
    
    Returns:
        (preprocess_status, reasons): A tuple containing the string status and a list of reason codes.
    """
    
    status_field = getattr(event, "status", None)
    
    # 1. Fast-path for MALFORMED events from Parser (Part 1)
    if status_field == "MALFORMED":
        error_info = getattr(event, "error_info", None) or {}
        layer = error_info.get("layer", "unknown_layer")
        # Return immediately to avoid cascading noisy "missing_X" reasons
        return "invalid", [f"malformed_{layer}"]
        
    # 2. Fast-path for UNKNOWN events (e.g., ARP, IPv6 at Data Link layer)
    if status_field == "UNKNOWN":
        return "partial", ["unsupported_network"]

    is_invalid = False
    is_partial = False
    reasons: Set[str] = set()

    # 3. Required Fields Verification
    required_fields = ["packet_id", "timestamp", "src_ip", "dst_ip", "network_protocol"]
    for field in required_fields:
        val = getattr(event, field, None)
        if val is None or val == "":
            is_invalid = True
            reasons.add(f"missing_{field}")

    # 4. Network Protocol Validation
    net_proto_raw = getattr(event, "network_protocol", None)
    if net_proto_raw:
        net_proto_upper = str(net_proto_raw).upper()
        # Accept both "IPV4" and the "IP" alias (Normalizer will unify them)
        if net_proto_upper not in ("IPV4", "IP"):
            is_partial = True
            reasons.add(f"unsupported_network:{net_proto_raw}")

    # 5. Transport Protocol & Port Requirements
    trans_proto_raw = getattr(event, "transport_protocol", None)
    trans_proto_upper = str(trans_proto_raw).upper() if trans_proto_raw else None

    if not trans_proto_raw:
        # Determine specific reason using IP Protocol number if transport is missing
        net_fields = getattr(event, "network_fields", None) or {}
        ip_proto = net_fields.get("ip_proto_number")
        
        if ip_proto in (6, 17, None):
            is_partial = True
            reasons.add("missing_transport")
        elif ip_proto == 1:
            is_partial = True
            reasons.add("unsupported_transport:ICMP")
        else:
            is_partial = True
            reasons.add(f"unsupported_transport:{ip_proto}")
    else:
        # Transport protocol exists, check if it's supported
        if trans_proto_upper in ("TCP", "UDP"):
            for field in ["src_port", "dst_port"]:
                val = getattr(event, field, None)
                if val is None:
                    is_invalid = True
                    reasons.add(f"missing_{field}")
        else:
            is_partial = True
            reasons.add(f"unsupported_transport:{trans_proto_raw}")

    # 6. Port Value Validation (Only check if we expect them)
    def validate_port(port_val: Any, port_name: str) -> None:
        nonlocal is_invalid, is_partial
        if port_val is None:
            return
        # Python's bool is a subclass of int (True == 1). We must explicitly reject it.
        if isinstance(port_val, bool) or not isinstance(port_val, int):
            is_invalid = True
            reasons.add(f"invalid_{port_name}")
            return
            
        if not (0 <= port_val <= 65535):
            is_invalid = True
            reasons.add(f"invalid_{port_name}")
        elif port_val == 0:
            is_partial = True
            reasons.add("reserved_port_0")

    if trans_proto_upper in ("TCP", "UDP"):
        validate_port(getattr(event, "src_port", None), "src_port")
        validate_port(getattr(event, "dst_port", None), "dst_port")

    # 7. Timestamp Validation
    ts = getattr(event, "timestamp", None)
    if ts is not None:
        if isinstance(ts, bool) or not isinstance(ts, (int, float)):
            is_invalid = True
            reasons.add("invalid_timestamp")
        else:
            try:
                # Catch math.isfinite(10**400) throwing OverflowError
                if not math.isfinite(ts) or ts <= 0:
                    is_invalid = True
                    reasons.add("invalid_timestamp")
                else:
                    # Reading directly from config without try/except (safe_stage catches missing keys)
                    skew_sec = float(cfg["preprocessor"]["max_future_timestamp_skew_sec"])
                    if ts > time.time() + skew_sec:
                        is_invalid = True
                        reasons.add("future_timestamp")
            except OverflowError:
                is_invalid = True
                reasons.add("invalid_timestamp")

    # 8. TCP Flags Validation
    if trans_proto_upper == "TCP":
        t_fields = getattr(event, "transport_fields", None) or {}
        flags = t_fields.get("flags")
        if flags is not None:
            if not isinstance(flags, list):
                is_invalid = True
                reasons.add("invalid_tcp_flags")
            else:
                for f in flags:
                    if not isinstance(f, str) or f.upper() not in _VALID_TCP_FLAGS:
                        is_invalid = True
                        reasons.add("invalid_tcp_flags")
                        break

    # 9. Inherit decode_status
    if getattr(event, "decode_status", None) in ("PARTIAL", "FAILED"):
        is_partial = True

    # --- Determine Final Preprocess Status ---
    if is_invalid:
        status = "invalid"
    elif is_partial:
        status = "partial"
    else:
        status = "valid"

    return status, sorted(list(reasons))