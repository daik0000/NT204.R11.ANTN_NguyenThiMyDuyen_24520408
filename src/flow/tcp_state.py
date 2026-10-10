from typing import Any, Set

# TCP States Constants
TCP_STATE_HANDSHAKE = "HANDSHAKE"
TCP_STATE_ESTABLISHED = "ESTABLISHED"
TCP_STATE_CLOSING = "CLOSING"
TCP_STATE_CLOSED = "CLOSED"
TCP_STATE_RESET = "RESET"

def normalize_flags(flags: Any) -> Set[str]:
    """Extracts and normalizes a collection of TCP flags into a standardized upper-case set."""
    if isinstance(flags, (list, tuple, set, frozenset)):
        return {str(f).upper() for f in flags}
    return set()

def next_state(
    current_state: str, 
    flags: Any, 
    direction: str, 
    ctx: dict, 
    is_first_packet: bool = False
) -> str:
    """
    Computes the next TCP state based on the current state, TCP flags, direction, 
    and flow context. This function has no side-effects other than updating the `ctx` dict.
    
    Priority strictly enforced: RST > SYN > FIN > ACK
    """
    flag_set = normalize_flags(flags)

    has_rst = "RST" in flag_set
    has_syn = "SYN" in flag_set
    has_fin = "FIN" in flag_set
    has_ack = "ACK" in flag_set

    # Terminal states: late packets do not alter the state.
    if current_state in (TCP_STATE_CLOSED, TCP_STATE_RESET):
        return current_state

    # --- 1. RST Processing ---
    if has_rst:
        return TCP_STATE_RESET

    # --- 2. SYN Processing ---
    if has_syn:
        if is_first_packet:
            if has_ack:
                ctx["midstream"] = True
                ctx["synack_seen"] = True
                ctx["synack_dir"] = direction
            return TCP_STATE_HANDSHAKE
            
        # Normal 3-way handshake SYN/ACK from responder
        if current_state == TCP_STATE_HANDSHAKE and has_ack and direction == "backward":
            ctx["synack_seen"] = True
            ctx["synack_dir"] = direction
            return TCP_STATE_HANDSHAKE
            
        # SYN in other states or directions is ignored (retransmit or anomalous payload scan)
        return current_state

    # --- 3. FIN Processing ---
    if has_fin:
        if is_first_packet:
            ctx["midstream"] = True
            
        if direction == "forward":
            ctx["fin_fwd"] = True
        else:
            ctx["fin_bwd"] = True
            
        if ctx.get("fin_fwd") and ctx.get("fin_bwd"):
            if not ctx.get("tcp_close_requires_final_ack"):
                return TCP_STATE_CLOSED
        return TCP_STATE_CLOSING

    # --- 4. ACK Processing ---
    if has_ack:
        if is_first_packet:
            ctx["midstream"] = True
            return TCP_STATE_ESTABLISHED
            
        # Final step of 3-way handshake, handles midstream SYN/ACK properly
        if current_state == TCP_STATE_HANDSHAKE and ctx.get("synack_seen") and direction != ctx.get("synack_dir"):
            return TCP_STATE_ESTABLISHED
            
        # Final ACK after both FINs are seen (if configured)
        if current_state == TCP_STATE_CLOSING:
            if ctx.get("fin_fwd") and ctx.get("fin_bwd") and ctx.get("tcp_close_requires_final_ack"):
                return TCP_STATE_CLOSED
        return current_state

    # --- 5. Fallback ---
    # Handled packets without RST, SYN, FIN, ACK (e.g., NULL scan, PSH/URG only)
    if is_first_packet:
        ctx["midstream"] = True
        return TCP_STATE_ESTABLISHED
        
    return current_state