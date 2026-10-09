import re
from urllib.parse import unquote_to_bytes
from typing import Union, Tuple, Dict, Any, Optional
from src.decoder.charset import decode_bytes

# Regex to detect a '%' that is NOT followed by exactly 2 hex digits.
# Works directly on bytes. Negative lookahead ensures it catches '%zz', '%', '%1' etc.
_INVALID_PERCENT_RE = re.compile(b"%(?![0-9a-fA-F]{2})")


def _to_bytes(data: Union[str, bytes]) -> bytes:
    """Converts str to bytes safely; bytes are returned unchanged."""
    if isinstance(data, str):
        return data.encode('utf-8', errors='surrogateescape')
    return data


def percent_decode(
    data: Union[str, bytes], 
    passes: int = 1, 
    plus_as_space: bool = False, 
    charset_hint: Optional[str] = None
) -> Tuple[str, str, Dict[str, Any]]:
    """
    Decodes percent-encoded data safely at the byte level.
    
    Returns:
        (decoded_text, status, info_dict)
    """
    current_bytes = _to_bytes(data)

    encodings = []
    invalid_percent = False
    
    # '+' -> space is part of form encoding: apply it ONCE, before percent decoding.
    # Doing it first keeps a literal "%2B" decoding to '+' (and it is not repeated on later passes).
    if plus_as_space:
        current_bytes = current_bytes.replace(b'+', b' ')
    
    for _ in range(passes):
        if b'%' not in current_bytes:
            break
        
        # Check for malformed percent sequences before unquoting
        if _INVALID_PERCENT_RE.search(current_bytes):
            invalid_percent = True
        
        # unquote_to_bytes safely ignores invalid % sequences and leaves them as is
        new_bytes = unquote_to_bytes(current_bytes)
        if new_bytes == current_bytes:
            break # Stop early if no more decodable sequences exist
        
        current_bytes = new_bytes
        encodings.append("percent")

    # Delegate to charset decoder (Commit 2) to handle invalid UTF-8 bytes gracefully.
    # detect_binary=False: URL components are short and attacker-controlled, so they must never be
    # skipped as "binary" (e.g. "%00%00" has to stay visible instead of becoming an empty string).
    text, status, info = decode_bytes(current_bytes, charset_hint, detect_binary=False)
    
    if encodings:
        info["encodings"] = encodings
        
    if invalid_percent:
        info["reason"] = "invalid_percent_sequence"
        # Downgrade status if it was OK, but don't overwrite a FAILED status from charset
        if status == "OK":
            status = "PARTIAL"
            
    return text, status, info


def decode_uri(uri: str, passes: int = 1, plus_as_space_in_query: bool = True) -> Dict[str, Any]:
    """
    Decodes a full raw HTTP URI.
    '+' is turned into a space ONLY after the first '?' (the query string), never in the path.
    The whole URI is decoded in one go, so status, invalid_byte_count and first_invalid_offset
    (offset in the decoded bytes) all refer to the full URI.
    Returns a dict suitable for decoded_fields["uri"].
    """
    raw = _to_bytes(uri)
    
    query_start = raw.find(b'?')
    if plus_as_space_in_query and query_start != -1:
        raw = raw[:query_start + 1] + raw[query_start + 1:].replace(b'+', b' ')
    
    text, status, info = percent_decode(raw, passes, plus_as_space=False)
    return {"value": text, "status": status, **info}


def _decode_x_www_form_urlencoded(
    data: Union[str, bytes], 
    passes: int = 1, 
    plus_as_space: bool = True, 
    charset_hint: Optional[str] = None
) -> Dict[str, Any]:
    """
    Internal generic decoder for application/x-www-form-urlencoded payloads.
    Splits by '&' and '=', decodes keys and values while preserving duplicates and order.
    """
    current_bytes = _to_bytes(data)

    if not current_bytes:
        return {"value": [], "status": "SKIPPED"}

    pairs = []
    overall_status = "OK"
    max_encodings = []
    reasons = set()
    invalid_byte_count = 0
    
    for pair_bytes in current_bytes.split(b'&'):
        if not pair_bytes:
            continue
        
        if b'=' in pair_bytes:
            k_bytes, v_bytes = pair_bytes.split(b'=', 1)
        else:
            k_bytes, v_bytes = pair_bytes, b""
            
        k_text, k_status, k_info = percent_decode(k_bytes, passes, plus_as_space, charset_hint)
        v_text, v_status, v_info = percent_decode(v_bytes, passes, plus_as_space, charset_hint)
        
        pairs.append((k_text, v_text))
        
        # Aggregate status
        for st in (k_status, v_status):
            if st == "FAILED":
                overall_status = "FAILED"
            elif st == "PARTIAL" and overall_status != "FAILED":
                overall_status = "PARTIAL"
                
        # Aggregate encodings, reasons and invalid byte counts
        for info in (k_info, v_info):
            if len(info.get("encodings", [])) > len(max_encodings):
                max_encodings = info["encodings"]
            if "reason" in info:
                reasons.add(info["reason"])
            invalid_byte_count += info.get("invalid_byte_count", 0)

    result = {
        "value": pairs,
        "status": overall_status
    }
    if max_encodings:
        result["encodings"] = max_encodings
    if reasons:
        result["reason"] = ", ".join(sorted(reasons))
    if invalid_byte_count:
        result["invalid_byte_count"] = invalid_byte_count
        
    return result


def decode_query(query_string: str, passes: int = 1, plus_as_space: bool = True) -> Dict[str, Any]:
    """Alias for decoding query string parameters."""
    return _decode_x_www_form_urlencoded(query_string, passes, plus_as_space)


def decode_form_body(body_bytes: bytes, passes: int = 1, plus_as_space: bool = True, charset_hint: Optional[str] = None) -> Dict[str, Any]:
    """Alias for decoding HTTP body encoded as application/x-www-form-urlencoded."""
    return _decode_x_www_form_urlencoded(body_bytes, passes, plus_as_space, charset_hint)