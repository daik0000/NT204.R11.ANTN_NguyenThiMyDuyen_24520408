from typing import Any
from src.utils.safe import safe_stage
from src.decoder.url_decoder import decode_uri, decode_form_body
from src.decoder.charset import decode_bytes
from src.decoder.html_decoder import apply_html_decoding
from src.decoder.mime_decoder import decode_mime_body

# Status ranking to determine the overall event decode_status
_STATUS_RANK = {"FAILED": 4, "PARTIAL": 3, "OK": 2, "SKIPPED": 1, None: 0}

# Constants for binary detection heuristics
_BINARY_PREFIXES = ("image/", "audio/", "video/", "font/")
_BINARY_TYPES = {
    "application/octet-stream", "application/zip", "application/pdf", 
    "application/gzip", "application/x-gzip", "application/x-zip-compressed"
}

@safe_stage("decoder")
def decode_event(event: Any, cfg: Any) -> Any:
    """
    The orchestrator for the Decoding pipeline.
    Limits payload sizes, routes to appropriate decoders based on app_protocol,
    and aggregates the final decode_status.
    
    Crucial: NEVER modifies event.app_fields directly to preserve raw evidence.
    """
    # Dictionary access (fixed from attribute access issue)
    dec_cfg = cfg["decoder"]
    
    # Skip if parser already marked it malformed, or if decoder is disabled in config
    if getattr(event, "status", None) == "MALFORMED" or not dec_cfg["enabled"]:
        event.decode_status = None
        return event

    event.decoded_fields = {}
    max_payload = dec_cfg["max_payload_bytes"]
    url_passes = dec_cfg["url_decode_passes"]
    plus_as_space = dec_cfg["plus_as_space_in_query"]
    html_content_types = dec_cfg["html_entity_content_types"]

    app_proto = str(getattr(event, "app_protocol", "")).upper()
    app_fields = getattr(event, "app_fields", None) or {}
    payload = getattr(event, "payload", None)
    
    # Track overall truncation
    truncated_by_limit = False

    # --- HTTP Routing ---
    if app_proto == "HTTP":
        # 1. Decode URI (Never apply HTML decoding to URI)
        if "uri" in app_fields:
            event.decoded_fields["uri"] = decode_uri(
                app_fields["uri"], 
                passes=url_passes, 
                plus_as_space_in_query=plus_as_space
            )

        # 2. Decode HTTP Body
        if payload and app_fields.get("body_offset") is not None:
            body_offset = app_fields["body_offset"]
            body_bytes = payload[body_offset:]
            
            # Truncate based on content-length to drop excess pipelined request data
            content_length = app_fields.get("content_length")
            if content_length is not None and content_length >= 0:
                body_bytes = body_bytes[:content_length]
            
            # Truncate if exceeds limit (Defends against memory exhaustion)
            if len(body_bytes) > max_payload:
                body_bytes = body_bytes[:max_payload]
                truncated_by_limit = True

            content_type = (app_fields.get("content_type") or "").lower()
            charset_hint = app_fields.get("charset")
            
            # Determine if binary content based on Content-Type header
            is_binary = content_type.startswith(_BINARY_PREFIXES) or content_type in _BINARY_TYPES

            if is_binary:
                event.decoded_fields["body"] = {"value": "", "status": "SKIPPED", "reason": "binary_content"}
            elif content_type == "application/x-www-form-urlencoded":
                # URL percent + form decode
                form_res = decode_form_body(
                    body_bytes, 
                    passes=url_passes, 
                    plus_as_space=plus_as_space, 
                    charset_hint=charset_hint
                )
                # Then HTML unescape values/keys ONLY if content type allows it
                if content_type in html_content_types:
                    form_res = apply_html_decoding(form_res)
                event.decoded_fields["form_params"] = form_res
            else:
                # Standard Charset decode (detect_binary=True defaults still apply internally)
                text, b_status, b_info = decode_bytes(body_bytes, charset_hint)
                body_res = {"value": text, "status": b_status, **b_info}
                
                # Apply HTML unescape ONLY if the content type implies it contains HTML entities
                if content_type in html_content_types:
                    body_res = apply_html_decoding(body_res)
                    
                event.decoded_fields["body"] = body_res

    # --- SMTP Routing ---
    elif app_proto == "SMTP" and app_fields.get("type") == "data":
        if payload and app_fields.get("body_offset") is not None:
            body_offset = app_fields["body_offset"]
            
            # Check length constraint for MIME body too
            if len(payload) - body_offset > max_payload:
                # Create a truncated payload to pass to mime_decoder
                payload = payload[:body_offset + max_payload]
                truncated_by_limit = True
                
            mime_headers = app_fields.get("mime_headers", {})
            event.decoded_fields["body"] = decode_mime_body(payload, body_offset, mime_headers)

    # --- Aggregate Overall Decode Status ---
    if not event.decoded_fields:
        event.decode_status = "SKIPPED"
    else:
        # Determine the worst status among all decoded fields
        worst_status = "SKIPPED"
        for field_result in event.decoded_fields.values():
            st = field_result.get("status", "SKIPPED")
            if _STATUS_RANK.get(st, 0) > _STATUS_RANK.get(worst_status, 0):
                worst_status = st
                
        # If the payload was truncated, the best it can be is PARTIAL
        if truncated_by_limit:
            event.reason.append("truncated_by_limit")
            if worst_status in ("OK", "SKIPPED"):
                worst_status = "PARTIAL"
                
        event.decode_status = worst_status

    return event