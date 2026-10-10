import ipaddress
import re
from datetime import datetime, timezone
from typing import Any, List, Optional
from src.preprocessor.aliases import PROTO_ALIASES

# Regex to find percent-encoded characters to uppercase their hex part (e.g., %2f -> %2F)
_HEX_PCT_RE = re.compile(r'%([0-9a-fA-F]{2})')

def _uppercase_hex(match: re.Match) -> str:
    """Helper to uppercase the hex digits in a percent encoding."""
    return f"%{match.group(1).upper()}"

def normalize_domain(domain: str) -> str:
    """
    Strips whitespace, lowercases, and removes exactly ONE trailing dot
    (e.g., 'WwW.ExAmPlE.CoM.' -> 'www.example.com').
    """
    domain = domain.strip().lower()
    if domain.endswith('.'):
        domain = domain[:-1]
    return domain

def normalize_host(host_str: str) -> str:
    """
    Normalizes a Host header or domain, keeping the port intact if present.
    Example.COM:8080 -> example.com:8080
    [IPv6]:Port -> [ipv6]:port
    """
    host_str = host_str.strip()
    if not host_str:
        return host_str
    
    # Handle IPv6 with brackets (e.g., [2001:db8::1]:8080)
    if host_str.startswith('['):
        end_bracket = host_str.rfind(']')
        if end_bracket != -1:
            domain_part = host_str[1:end_bracket].lower()
            rest = host_str[end_bracket+1:]
            return f"[{domain_part}]{rest}"
            
    # Handle IPv4 or Domain with port
    if ':' in host_str:
        parts = host_str.rsplit(':', 1)
        # Verify if the part after the last colon is actually a port number
        if parts[1].isdigit():
            return f"{normalize_domain(parts[0])}:{parts[1]}"
            
    # Pure domain, IPv4 without port, or raw IPv6
    return normalize_domain(host_str)

def normalize_uri_path(path: str, method: Optional[str] = None) -> str:
    """
    Safely normalizes URI paths:
    - Uppercase percent-encoded hex chars (%2f -> %2F).
    - Ensure origin-form paths start with '/', EXCEPT for CONNECT methods.
    - Does NOT collapse '//' or resolve '/../' to preserve traversal evidence.
    """
    if not path:
        return "/"
        
    path = _HEX_PCT_RE.sub(_uppercase_hex, path)
    
    if isinstance(method, str) and method.upper() == "CONNECT":
        return path
    
    # Case-insensitive scheme check
    path_lower = path.lower()
    valid_starts = ('http://', 'https://', 'ftp://', 'ws://', 'wss://', 'urn:', '*', '/')
    
    if not path_lower.startswith(valid_starts):
        path = '/' + path
        
    return path

def normalize(event: Any, cfg: Any) -> List[str]:
    """
    Applies unified normalization rules to an IDSEvent without overwriting raw evidence.
    Returns: List of field names that were changed (e.g., ["timestamp", "src_ip", "path"]).
    """
    changes = []
    
    # --- 1. Timestamp Normalization ---
    try:
        ts = getattr(event, "timestamp", None)
        if ts is not None:
            float_ts = float(ts)
            ts_changed = False
            
            # Only mark "timestamp" as changed if the value/type actually mutated
            if type(ts) is not float or ts != float_ts:
                event.timestamp = float_ts
                ts_changed = True
            
            # Always populate ISO timestamp, but don't count it as a "change" flag by itself
            iso_val = datetime.fromtimestamp(float_ts, timezone.utc).isoformat()
            if getattr(event, "timestamp_iso", None) != iso_val:
                event.timestamp_iso = iso_val
                
            if ts_changed and "timestamp" not in changes:
                changes.append("timestamp")
    except (ValueError, TypeError, OSError, OverflowError):
        pass # Validator handles invalid timestamps

    # --- 2. Protocol Alias Normalization ---
    for proto_attr in ["network_protocol", "transport_protocol", "app_protocol"]:
        proto_raw = getattr(event, proto_attr, None)
        if isinstance(proto_raw, str):
            proto_std = PROTO_ALIASES.get(proto_raw.lower(), proto_raw)
            if proto_std != proto_raw:
                setattr(event, proto_attr, proto_std)
                changes.append(proto_attr)

    # --- 3. IP Address Formatting ---
    # IP validation (detecting garbage IPs) is handled by the Validator. Normalizer only formats.
    for field in ["src_ip", "dst_ip"]:
        ip_raw = getattr(event, field, None)
        if isinstance(ip_raw, str) and ip_raw:
            try:
                ip_std = ipaddress.ip_address(ip_raw.strip()).compressed
                if ip_std != ip_raw:
                    setattr(event, field, ip_std)
                    changes.append(field)
            except ValueError:
                # Malformed IP string -> inject reason (but don't crash or alter valid status)
                if not hasattr(event, "reason"):
                    event.reason = []
                reason_msg = f"invalid_{field}_format"
                if reason_msg not in event.reason:
                    event.reason.append(reason_msg)

    # --- 4. Application Fields (HTTP/DNS) Normalization ---
    app_fields = getattr(event, "app_fields", None)
    if isinstance(app_fields, dict):
        
        # A) HTTP host: always write the view, report "domain" only if it differs from raw
        if isinstance(app_fields.get("host"), str):
            norm_host = normalize_host(app_fields["host"])
            app_fields["host_normalized"] = norm_host
            if norm_host != app_fields["host"]:
                changes.append("domain")
                
        # B) DNS: always emit the normalized views, report "domain" only if something differs
        if getattr(event, "app_protocol", None) == "DNS":
            domain_changed = False
            if isinstance(app_fields.get("queries"), list):
                norm_queries = []
                for q in app_fields["queries"]:
                    if isinstance(q, dict) and isinstance(q.get("name"), str):
                        new_q = dict(q)
                        new_q["name"] = normalize_domain(q["name"])
                        domain_changed |= new_q["name"] != q["name"]
                        norm_queries.append(new_q)
                    else:
                        norm_queries.append(q)  # keep malformed elements untouched
                app_fields["queries_normalized"] = norm_queries
            if isinstance(app_fields.get("answers"), list):
                norm_answers = []
                for a in app_fields["answers"]:
                    if isinstance(a, dict):
                        new_a = dict(a)
                        if isinstance(a.get("name"), str):
                            new_a["name"] = normalize_domain(a["name"])
                        # only record types whose data is a domain name; TXT/A keep their case
                        if a.get("type") in ("CNAME", "NS") and isinstance(a.get("data"), str):
                            new_a["data"] = normalize_domain(a["data"])
                        domain_changed |= new_a != a
                        norm_answers.append(new_a)
                    else:
                        norm_answers.append(a)
                app_fields["answers_normalized"] = norm_answers
            if domain_changed:
                changes.append("domain")

        # C) HTTP headers: always write the view; report "headers" only if it differs from raw pairs
        header_pairs = app_fields.get("header_pairs")
        if isinstance(header_pairs, list):
            norm_headers = {}
            headers_changed = False
            valid_pairs = 0
            for pair in header_pairs:
                if not isinstance(pair, (list, tuple)) or len(pair) != 2:
                    continue
                k_raw, v_raw = pair
                if not isinstance(k_raw, str) or not isinstance(v_raw, str):
                    continue
                valid_pairs += 1
                k = k_raw.strip().lower()
                v = v_raw.strip()
                headers_changed |= (k != k_raw or v != v_raw)
                # RFC 7230: set-cookie MUST remain a list, everything else is joined by ", "
                if k == "set-cookie":
                    norm_headers.setdefault(k, []).append(v)
                elif k not in norm_headers:
                    norm_headers[k] = v
                else:
                    norm_headers[k] = f"{norm_headers[k]}, {v}"
            if isinstance(norm_headers.get("host"), str):
                new_host = normalize_host(norm_headers["host"])
                headers_changed |= new_host != norm_headers["host"]
                norm_headers["host"] = new_host
            # fewer emitted values than valid pairs means duplicate headers were merged
            emitted = sum(len(v) if isinstance(v, list) else 1 for v in norm_headers.values())
            headers_changed |= emitted != valid_pairs
            app_fields["headers_normalized"] = norm_headers
            if headers_changed:
                changes.append("headers")

        # D) URI Path Normalization
        path_source = None
        method = app_fields.get("method")
        
        # Priority: Raw URI -> Raw Path. We NEVER use the output from the Decoder
        # because percent-decoded URI has already lost its %hex capitalization.
        if "uri" in app_fields and isinstance(app_fields["uri"], str):
            full_raw_uri = app_fields["uri"]
            path_source = full_raw_uri.split('?')[0] # Only take part before query string
        elif "path" in app_fields and isinstance(app_fields["path"], str):
            full_raw_path = app_fields["path"]
            path_source = full_raw_path.split('?')[0]

        if isinstance(path_source, str):
            norm_path = normalize_uri_path(path_source, method=method)
            app_fields["path_normalized"] = norm_path          # always write the view
            if norm_path != path_source:                       # compare with RAW, not with the old view
                changes.append("path")

    # Return unique, sorted list of changes to inform orchestrator
    return sorted(list(set(changes)))