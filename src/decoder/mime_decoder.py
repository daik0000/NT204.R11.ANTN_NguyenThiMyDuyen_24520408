import base64
import quopri
import re
import binascii
from typing import Dict, Any
from src.decoder.charset import decode_bytes

# Regex to keep only valid Base64 characters
_B64_CLEAN_RE = re.compile(br'[^A-Za-z0-9+/]')

# Regex to remove SMTP DATA termination marker at the end
_SMTP_TERM_RE = re.compile(rb"(?:\r?\n|^)\.\r?\n$")

def _clean_base64(data: bytes) -> bytes:
    """Removes invalid base64 characters and fixes missing padding '='."""
    cleaned = _B64_CLEAN_RE.sub(b'', data)
    pad_len = (4 - (len(cleaned) % 4)) % 4
    return cleaned + (b'=' * pad_len)

def decode_mime_body(payload: bytes, body_offset: int, mime_headers: Dict[str, Any]) -> Dict[str, Any]:
    """
    Decodes an SMTP MIME body using Content-Transfer-Encoding and Content-Type.
    
    Returns a dictionary suitable for event.decoded_fields["body"].
    """
    if not payload or body_offset is None or body_offset >= len(payload):
        return {"value": "", "status": "SKIPPED", "reason": "empty_payload"}

    body_bytes = payload[body_offset:]
    
    # Remove SMTP DATA termination marker if present
    body_bytes = _SMTP_TERM_RE.sub(b"", body_bytes)
    
    cte = str(mime_headers.get("content-transfer-encoding") or "").strip().lower()
    content_type = str(mime_headers.get("content-type") or "").strip().lower()
    
    # Extract charset from Content-Type if present (e.g., "text/plain; charset=utf-8")
    charset_hint = None
    if "charset=" in content_type:
        parts = content_type.split("charset=")
        if len(parts) > 1:
            charset_hint = parts[1].split(";")[0].strip('"\'')

    decoded_raw_bytes = body_bytes
    encodings = []
    decode_status = "OK"
    reasons = set()
    unsupported_cte = False

    # 1. Transfer-Encoding decoding (Bytes -> Bytes)
    if cte == "base64":
        # Remove whitespaces/newlines before strict decoding
        no_space_bytes = b"".join(body_bytes.split())
        try:
            # validate=True rejects non-alphabet characters, throwing binascii.Error
            decoded_raw_bytes = base64.b64decode(no_space_bytes, validate=True)
            encodings.append("base64")
        except binascii.Error:
            # Malformed base64 (e.g., missing padding, injected junk characters)
            cleaned_bytes = _clean_base64(body_bytes)
            try:
                decoded_raw_bytes = base64.b64decode(cleaned_bytes)
                encodings.append("base64")
                decode_status = "PARTIAL"
                reasons.add("malformed_base64_cleaned")
            except Exception:
                # Total failure
                decoded_raw_bytes = body_bytes
                decode_status = "FAILED"
                reasons.add("base64_decode_failed")
                
    elif cte == "quoted-printable":
        try:
            decoded_raw_bytes = quopri.decodestring(body_bytes)
            encodings.append("quoted-printable")
        except Exception:
            decode_status = "FAILED"
            reasons.add("quopri_decode_failed")
            
    elif cte in ("", "7bit", "8bit", "binary"):
        # No transformation needed, remains OK
        pass
        
    else:
        # Unsupported transfer encoding (e.g., x-uuencode, mac-binhex40)
        unsupported_cte = True
        reasons.add(f"unsupported_encoding:{cte[:30]}")

    # If completely failed at the transfer level, return early holding text fallback
    if decode_status == "FAILED":
        # Fallback to string representation to avoid JSON serialization crash
        text_fallback, _, _ = decode_bytes(body_bytes, charset_hint, detect_binary=False)
        result = {"value": text_fallback, "status": "FAILED"}
        if reasons:
            result["reason"] = ", ".join(sorted(reasons))
        return result

    # 2. Charset decoding (Bytes -> String)
    # Use detect_binary=True because email bodies can legitimately be binary attachments.
    text, charset_status, charset_info = decode_bytes(decoded_raw_bytes, charset_hint, detect_binary=True)
    
    # Merge statuses (FAILED > PARTIAL > OK > SKIPPED)
    final_status = decode_status
    if charset_status == "SKIPPED" and decode_status in ("OK", "SKIPPED"):
        final_status = "SKIPPED"
    elif charset_status == "PARTIAL" and final_status != "FAILED":
        final_status = "PARTIAL"
    elif charset_status == "FAILED":
        final_status = "FAILED"

    # Downgrade an "OK" to "SKIPPED" if we couldn't process the CTE
    if unsupported_cte and final_status == "OK":
        final_status = "SKIPPED"

    result = {
        "value": text,
        "status": final_status
    }
    
    if encodings:
        result["encodings"] = encodings
        
    # Merge charset info output (like invalid_byte_count, charset used)
    for k, v in charset_info.items():
        if k == "reason":
            reasons.add(v)
        else:
            result[k] = v
            
    if reasons:
        result["reason"] = ", ".join(sorted(reasons))
        
    return result