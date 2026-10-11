import math
from typing import Any
from src.flow.flow_table import FlowEntry

# Must stay identical to the defaults in settings.yaml (section "flow").
DEFAULTS = {
    "udp_idle_timeout_sec": 60.0,
    "tcp_handshake_timeout_sec": 30.0,
    "tcp_closed_linger_sec": 10.0,
    "tcp_idle_timeout_sec": 300.0,
}


def _get(flow_cfg: Any, key: str) -> float:
    """Read a positive finite timeout from the 'flow' config section, else the default."""
    v = flow_cfg.get(key) if isinstance(flow_cfg, dict) else None
    if type(v) in (int, float) and math.isfinite(v) and v > 0:
        return float(v)
    return DEFAULTS[key]


def timeout_for(entry: FlowEntry, flow_cfg: Any) -> float:
    """
    Determines the appropriate timeout value based on flow protocol and state.
    
    Args:
        entry: The FlowEntry to evaluate.
        flow_cfg: The 'flow' section dictionary from settings.yaml (cfg['flow']).
    """
    flow = entry.flow
    proto = flow.protocol
    state = flow.state
    
    # UDP has a single fixed idle timeout
    if proto == "UDP":
        return _get(flow_cfg, "udp_idle_timeout_sec")
        
    # TCP Rules based on current connection state
    if state == "HANDSHAKE":
        return _get(flow_cfg, "tcp_handshake_timeout_sec")
    elif state in ("CLOSED", "RESET"):
        return _get(flow_cfg, "tcp_closed_linger_sec")
    else:
        # Covers ESTABLISHED, CLOSING, and any other transitional states
        return _get(flow_cfg, "tcp_idle_timeout_sec")


def is_expired(entry: FlowEntry, now: float, flow_cfg: Any) -> bool:
    """
    Checks if a flow has expired. 
    Strict inequality (>) is used: now - last_seen > timeout.
    
    Args:
        entry: The FlowEntry to evaluate.
        now: Current event-time watermark.
        flow_cfg: The 'flow' section dictionary from settings.yaml (cfg['flow']).
    """
    timeout = timeout_for(entry, flow_cfg)
    return (now - entry.flow.last_seen) > timeout


def get_close_reason(entry: FlowEntry) -> str:
    """
    Determines the specific close_reason for a flow that has timed out,
    meaning it has exceeded its linger or idle limits.
    """
    state = entry.flow.state
    if state == "CLOSED":
        return "tcp_closed"
    if state == "RESET":
        return "tcp_reset"
    if state == "HANDSHAKE":
        return "handshake_timeout"
        
    return "idle_timeout"