import logging
from typing import Dict, Any

from src.models.event import IDSEvent 
from src.parsers.network.ipv4_parser import parse_ipv4
from src.parsers.transport.tcp_parser import parse_tcp
from src.parsers.transport.udp_parser import parse_udp
from src.parsers.application.detector import detect_application_protocol
from src.parsers.application.http_parser import parse_http
from src.parsers.application.dns_parser import parse_dns
from src.parsers.application.smtp_parser import parse_smtp

logger = logging.getLogger(__name__)

IP_PROTO_TO_NAME = {
    6: "TCP", 
    17: "UDP"
}

def load_unknown_policy(config_path: str = "config/settings.yaml") -> str:
    try:
        path = Path(config_path)
        if not path.is_file():
            logger.debug("Config file %s not found. Using default policy: 'log'", config_path)
            return "log"
        with open(path, "r", encoding="utf-8") as f:
            config = yaml.safe_load(f)
        return str(config.get("unknown_policy", "log")).lower()
    except Exception as e:
        logger.warning("Failed to read unknown_policy from %s: %s. Using default: 'log'", config_path, e)
        return "log"
        
UNKNOWN_POLICY = load_unknown_policy()

def process_packet(timestamp: float, raw_bytes: bytes, packet_id: int) -> IDSEvent:
    """
    Orchestrates the packet analysis pipeline from L3 up to L7.
    Applies the Fall-through principle: an error at any layer finalizes the event at that layer.
    """
    event_dict: Dict[str, Any] = {
        "packet_id": packet_id,
        "timestamp": timestamp,
        "raw_length": len(raw_bytes),
        "payload_length": 0,
        "status": "OK",
        "error_info": None,
        "network_protocol": None,
        "src_ip": None,
        "dst_ip": None,
        "network_fields": None,
        "transport_protocol": None,
        "src_port": None,
        "dst_port": None,
        "transport_fields": None,
        "app_protocol": None,
        "detection_method": None,
        "app_fields": None
    }

    # 1. NETWORK LAYER
    net_result = parse_ipv4(raw_bytes)
    net_status = net_result.get("status")
    
    if net_status == "UNKNOWN":
        event_dict["status"] = "UNKNOWN"
        return IDSEvent(**event_dict)

    if net_status == "MALFORMED":
        event_dict["status"] = "MALFORMED"
        event_dict["error_info"] = net_result.get("error_info")
        return IDSEvent(**event_dict)

    network_fields = net_result.get("network_fields") or {}
    event_dict.update({
        "network_protocol": net_result.get("network_protocol"),
        "src_ip": net_result.get("src_ip"),
        "dst_ip": net_result.get("dst_ip"),
        "network_fields": network_fields
    })
    
    transport_payload = net_result.get("transport_payload", b"")
    event_dict["payload_length"] = len(transport_payload)
    
    ip_proto_number = network_fields.get("ip_proto_number")
    transport_proto = IP_PROTO_TO_NAME.get(ip_proto_number)

    if not transport_payload or not transport_proto:
        return IDSEvent(**event_dict)

    # 2. TRANSPORT LAYER 
    trans_result = parse_tcp(transport_payload) if transport_proto == "TCP" else parse_udp(transport_payload)

    if trans_result.get("status") == "MALFORMED":
        event_dict["status"] = "MALFORMED"
        event_dict["error_info"] = trans_result.get("error_info")
        return IDSEvent(**event_dict)

    event_dict.update({
        "transport_protocol": trans_result.get("transport_protocol"),
        "src_port": trans_result.get("src_port"),
        "dst_port": trans_result.get("dst_port"),
        "transport_fields": trans_result.get("transport_fields")
    })
    
    app_payload = trans_result.get("app_payload", b"")
    if not app_payload:
        return IDSEvent(**event_dict)

    # 3. DETECTOR (L7 Labeling)
    app_proto, det_method = detect_application_protocol(
        payload=app_payload, 
        src_port=event_dict["src_port"], 
        dst_port=event_dict["dst_port"],
        packet_id=packet_id
    )
    
    if app_proto == "UNKNOWN":
        if UNKNOWN_POLICY == "skip":
            event_dict["status"] = "IGNORED"
            # Do not set error_info since this is not an error; keep it as None
        else:
            event_dict["app_protocol"] = None
            event_dict["detection_method"] = det_method
        return IDSEvent(**event_dict)

    # If detection succeeds
    event_dict["app_protocol"] = app_proto
    event_dict["detection_method"] = det_method

    # 4. APPLICATION LAYER
    app_result = None
    if app_proto == "HTTP":
        app_result = parse_http(app_payload)
    elif app_proto == "DNS":
        app_result = parse_dns(app_payload)
    elif app_proto == "SMTP":
        app_result = parse_smtp(app_payload)

    if app_result:
        if app_result.get("status") == "MALFORMED":
            event_dict["status"] = "MALFORMED"
            event_dict["error_info"] = app_result.get("error_info")
        else:
            event_dict["app_fields"] = app_result.get("app_fields")
            event_dict["app_protocol"] = app_result.get("app_protocol", app_proto)

    return IDSEvent(**event_dict)