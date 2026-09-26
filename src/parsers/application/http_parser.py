from typing import Dict, Any
from src.utils.safe import safe_parse

@safe_parse
def parse_http(raw_bytes: bytes) -> Dict[str, Any]:
    """
    Parses an L7 payload into an HTTP request or response.
    
    KNOWN LIMITATIONS:
    1. TCP Fragmentation: The parser only operates on individual packets (stateless).
       TCP Reassembly for large fragmented payloads is not yet supported.
    2. Header Duplication: If multiple headers share the same name (e.g., Set-Cookie),
       the last value will overwrite previous ones.
    3. Obsolete Line Folding: Concatenation of headers spanning multiple lines is not yet supported.
    """
    if not raw_bytes:
        raise ValueError("Empty payload, cannot be HTTP.")

    # Split Header and Body by double CRLF (\r\n\r\n) per HTTP standard
    parts = raw_bytes.split(b'\r\n\r\n', 1)
    header_bytes = parts[0]
    body_bytes = parts[1] if len(parts) > 1 else b""

    header_text = header_bytes.decode('utf-8', errors='ignore')
    lines = header_text.split('\r\n')
    
    if not lines or not lines[0]:
        raise ValueError("Malformed HTTP: Start Line not found.")

    start_line = lines[0]
    tokens = start_line.split(' ')
    
    result = {
        "status": "OK",
        "app_protocol": "HTTP",
        "app_fields": {
            "headers": {}
        }
    }

    # 1. Parse Start Line
    if start_line.startswith("HTTP/"):
        # HTTP Response (e.g., HTTP/1.1 200 OK)
        # Strict validation: Status code must be numeric
        if len(tokens) >= 3 and tokens[1].isdigit():
            result["app_fields"]["type"] = "response"
            result["app_fields"]["version"] = tokens[0]
            result["app_fields"]["status_code"] = int(tokens[1])
            result["app_fields"]["reason"] = " ".join(tokens[2:])
        else:
            raise ValueError(f"Malformed HTTP response line: {start_line}")
    else:
        # HTTP Request (e.g., GET /admin HTTP/1.1)
        # Strict validation: Ensure the last token is actually an HTTP version declaration
        if len(tokens) >= 3 and tokens[2].startswith("HTTP/"):
            result["app_fields"]["type"] = "request"
            result["app_fields"]["method"] = tokens[0]
            result["app_fields"]["path"] = tokens[1]
            result["app_fields"]["version"] = tokens[2]
        else:
            raise ValueError(f"Malformed HTTP request line: {start_line}")

    # 2. Parse Headers
    content_length = 0
    for line in lines[1:]:
        if not line:
            continue
        if ':' in line:
            key, val = line.split(':', 1)
            key = key.strip()
            val = val.strip()
            result["app_fields"]["headers"][key] = val
            
            if key.lower() == 'content-length':
                try:
                    content_length = int(val)
                except ValueError:
                    pass

    # 3. Parse Body (if any)
    if body_bytes:
        actual_body = body_bytes[:content_length] if content_length > 0 else body_bytes
        result["app_fields"]["body_preview"] = actual_body[:1024].decode('utf-8', errors='replace')

    return result

if __name__ == "__main__":
    import pprint
    import logging
    
    logging.basicConfig(level=logging.DEBUG)
    print("=== TEST HTTP PARSER ===")
    
    # Test 1: Valid HTTP Request with Body
    print("\n--- Valid HTTP Request ---")
    req_payload = b"POST /api/login HTTP/1.1\r\nHost: example.com\r\nContent-Length: 27\r\n\r\nusername=admin&password=123"
    pprint.pprint(parse_http(req_payload))
    
    # Test 2: Valid HTTP Response
    print("\n--- Valid HTTP Response ---")
    resp_payload = b"HTTP/1.1 404 Not Found\r\nServer: nginx\r\n\r\n<html>Page Not Found</html>"
    pprint.pprint(parse_http(resp_payload))
    
    # Test 3: Malformed HTTP Response
    print("\n--- Malformed HTTP Response ---")
    malformed_resp_payload = b"HTTP/1.1 OK\r\nServer: nginx\r\n\r\nBody"
    pprint.pprint(parse_http(malformed_resp_payload))