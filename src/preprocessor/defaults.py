from typing import Any, List

def fill_defaults(event: Any) -> bool:
    """
    Ensures all expected nested keys exist with consistent default values.
    - scalars -> None
    - lists -> []
    - dicts -> {}
    
    Returns:
        bool: True if any default values were filled/mutated, False otherwise.
    """
    changed = False

    # 1) Four containers: repair anything that is not a dict (None, list, str, ...)
    for dict_field in ["network_fields", "transport_fields", "app_fields", "decoded_fields"]:
        if not isinstance(getattr(event, dict_field, None), dict):
            setattr(event, dict_field, {})
            changed = True

    # 2) reason must always be a list (later stages call .append on it)
    if not isinstance(getattr(event, "reason", None), list):
        event.reason = []
        changed = True

    # 3) flags default applies to TCP only, and also repairs flags=None
    t_fields = event.transport_fields
    if str(getattr(event, "transport_protocol", None)).upper() == "TCP" and t_fields.get("flags") is None:
        t_fields["flags"] = []
        changed = True

    # 4) Ensure L7 structure consistency (Protocol independent safe defaults)
    a_fields = event.app_fields
    app_proto = getattr(event, "app_protocol", None)
    
    if app_proto == "HTTP":
        if a_fields.get("headers") is None:
            a_fields["headers"] = {}
            changed = True
        if a_fields.get("header_pairs") is None:
            a_fields["header_pairs"] = []
            changed = True
            
    elif app_proto == "DNS":
        if a_fields.get("queries") is None:
            a_fields["queries"] = []
            changed = True
        if a_fields.get("answers") is None:
            a_fields["answers"] = []
            changed = True

    return changed


def apply_policies(
    event: Any, 
    status: str, 
    reasons: List[str], 
    cfg: Any, 
    has_normalizations: bool, 
    has_defaults: bool
) -> None:
    """
    Evaluates policies for invalid and unsupported data.
    Assigns final `preprocess_status` and `processing_action`.
    """
    prep_cfg = cfg["preprocessor"]
    
    # Defaults based on requirements:
    # unsupported_policy defaults to "mark" (logs ICMP/ARP consistently with Part 1)
    unsupported_policy = prep_cfg.get("unsupported_policy", "mark")
    invalid_policy = prep_cfg.get("invalid_policy", "flag")

    # Determine if the payload is an unsupported protocol (e.g., ARP, IPv6, ICMP)
    # Note: This checks for network/transport layers, completely decoupled from L7 `unknown_policy`.
    is_unsupported = any(
        r.startswith("unsupported_network") or r.startswith("unsupported_transport") 
        for r in reasons
    )

    action = "none"

    # --- 1. Terminal and Flagging Policies ---
    if status == "invalid":
        action = "dropped" if invalid_policy == "drop" else "flagged"
    elif is_unsupported:
        status = "partial" # Force partial for unsupported protocols if it wasn't already
        action = "skipped" if unsupported_policy == "skip" else "flagged"
        
    # --- 2. Benign Actions ---
    else:
        if has_normalizations:
            action = "normalized"
        elif has_defaults:
            action = "defaults_filled"

    # Save to event
    event.preprocess_status = status
    event.processing_action = action