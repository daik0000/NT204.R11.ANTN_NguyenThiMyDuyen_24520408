import re
from typing import Dict, Any
from src.utils.safe import safe_parse

# Regex for parsing server responses: 3 digits, followed by a space (final) or hyphen (more to come)
SMTP_RESP_RE = re.compile(r"^(\d{3})([ -])(.*)")

# RFC 5322 field name: printable ASCII except space and colon
HEADER_NAME_RE = re.compile(r"^[\x21-\x39\x3b-\x7e]+$")

# First blank line = end of the header section (CRLF or bare-LF line endings)
HEADER_END_RE = re.compile(rb"\r?\n\r?\n")

SMTP_COMMANDS = (
    "HELO", "EHLO", "MAIL FROM", "RCPT TO", "DATA", 
    "QUIT", "RSET", "AUTH", "STARTTLS", "VRFY", "EXPN", "NOOP"
)

@safe_parse
def parse_smtp(raw_bytes: bytes) -> Dict[str, Any]:
    """
    KNOWN LIMITATIONS:
    1. Per-packet parsing (Stateless). Does not track session state
    (e.g., whether the DATA command has been sent). Consequence: if email content (after DATA)
    happens to contain a line starting with 3 digits + space/hyphen, that packet will be MISCLASSIFIED
    as a "response" instead of being correctly identified as email content — this is an inherent limitation of the stateless per-packet design, not a bug.
    
    2. Email content that does not match the response/command pattern will be truncated to 100 characters per line to avoid bloating the JSON log.

    3. (Bai 2) Email content (type="data") is only recognized when the packet STARTS with RFC 5322
    header lines. Later body-only segments of a long message are not recognized (no TCP reassembly).
    """
    if not raw_bytes:
        raise ValueError("Empty payload, cannot be SMTP.")

    # Decode bytes safely to string. We keep original raw lines for accurate MIME parsing (Bai 2)
    text = raw_bytes.decode('utf-8', errors='replace')
    raw_lines = text.split('\r\n')
    if len(raw_lines) == 1 and '\n' in text:
        raw_lines = text.split('\n')

    first_non_empty = next((line for line in raw_lines if line.strip()), None)
    
    if not first_non_empty:
        raise ValueError("Payload contains only whitespace/empty lines.")

    # Determine packet type (command, response, or data) based on the first line
    is_response = bool(SMTP_RESP_RE.match(first_non_empty))
    
    # Bai 2: Detect SMTP DATA (MIME headers). Checked BEFORE the command prefixes, otherwise headers
    # such as "Authentication-Results:" or "Data:" would be misclassified as AUTH / DATA commands.
    # Real SMTP commands never look like "name: value" (MAIL FROM / RCPT TO contain a space).
    is_data = False
    if not is_response and ':' in first_non_empty:
        key = first_non_empty.split(':', 1)[0]
        if HEADER_NAME_RE.match(key):
            is_data = True

    is_command = (not is_response and not is_data
                  and first_non_empty.upper().startswith(SMTP_COMMANDS))

    if not is_response and not is_command and not is_data:
        raise ValueError(f"First line does not match SMTP standard: {first_non_empty[:50]}...")

    app_fields = {}

    if is_data:
        # --- Bai 2: SMTP DATA (MIME headers + body) ---
        app_fields["type"] = "data"
        app_fields["mime_headers"] = {}
        
        # Split header and body at the first blank line. Offsets are computed on the raw BYTES
        # so they stay valid for event.payload[body_offset:].
        # body_offset is None when no blank line was found (headers continue in a later segment).
        sep = HEADER_END_RE.search(raw_bytes)
        header_bytes = raw_bytes[:sep.start()] if sep else raw_bytes
        app_fields["body_offset"] = sep.end() if sep else None
        
        header_text = header_bytes.decode('utf-8', errors='replace')
        header_lines = re.split(r'\r?\n', header_text)
            
        current_key = None
        for line in header_lines:
            if not line:
                continue
            
            # Handle folded headers (lines starting with space or tab)
            if line[0] in (' ', '\t'):
                if current_key:
                    app_fields["mime_headers"][current_key] += " " + line.strip()
            elif ':' in line:
                k, v = line.split(':', 1)
                current_key = k.strip().lower()
                app_fields["mime_headers"][current_key] = v.strip()
                
    else:
        # --- Bai 1: Original Command/Response Logic ---
        app_fields["type"] = "response" if is_response else "command"
        app_fields["messages"] = []
        
        # Strip lines for commands and responses as expected by Bai 1 logic
        lines = [line.strip() for line in raw_lines if line.strip()]

        if is_response:
            for line in lines:
                match = SMTP_RESP_RE.match(line)
                if match:
                    code, separator, msg = match.groups()
                    app_fields["messages"].append({
                        "code": int(code),
                        "is_last_line": separator == " ",
                        "message": msg.strip()
                    })
                else:
                    # Lines without a code (may be part of long content or an abnormal payload)
                    app_fields["messages"].append({
                        "code": 0,
                        "is_last_line": False,
                        "message": line[:100] + ("..." if len(line) > 100 else "")
                    })
        else:
            for line in lines:
                upper_line = line.upper()
                matched_cmd = next((cmd for cmd in SMTP_COMMANDS if upper_line.startswith(cmd)), None)
                
                if matched_cmd:
                    # Extract arguments (skip the command itself and separators like space, colon)
                    raw_args = line[len(matched_cmd):].strip(": ")
                    app_fields["messages"].append({
                        "command": matched_cmd,
                        "arguments": raw_args
                    })
                else:
                    # Line is not a standard command (may be part of the email DATA stream)
                    app_fields["messages"].append({
                        "command": "UNKNOWN",
                        "arguments": line[:100] + ("..." if len(line) > 100 else "")
                    })

    return {
        "status": "OK",
        "app_protocol": "SMTP",
        "app_fields": app_fields
    }

if __name__ == "__main__":
    import pprint
    import logging
    
    logging.basicConfig(level=logging.DEBUG)
    print("=== TEST SMTP PARSER ===")
    
    # Test 1: SMTP Client Commands
    print("\n--- Valid SMTP Commands ---")
    cmd_payload = b"EHLO client.example.com\r\nMAIL FROM:\r\nRCPT TO: "
    pprint.pprint(parse_smtp(cmd_payload))
    
    # Test 2: SMTP Server Response
    print("\n--- Valid Multi-line SMTP Response ---")
    resp_payload = b"250-mail.example.com\r\n250-PIPELINING\r\n250-8BITMIME\r\n250 SMTPUTF8"
    pprint.pprint(parse_smtp(resp_payload))
    
    # Test 3: Malformed SMTP containing binary bytes
    print("\n--- Malformed/Binary Bytes Payload ---")
    malformed_payload = b"220 ESMTP Postfix\r\n\xff\xfe\x00\x00Ransomware_Garbage\r\n"
    pprint.pprint(parse_smtp(malformed_payload))

    # Test 4: Not SMTP
    print("\n--- Invalid Protocol (Garbage) ---")
    garbage_payload = b"SSH-2.0-OpenSSH_8.2p1\r\n"
    pprint.pprint(parse_smtp(garbage_payload))
    
    # Test 5: SMTP DATA (Bai 2 extension)
    print("\n--- Valid SMTP DATA (MIME headers + body) ---")
    data_payload = b"MIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: base64\r\nSubject: =?utf-8?B?SGVsbG8=?=\r\n Folded-Header: yes\r\n\r\nSGVsbG8gV29ybGQ="
    pprint.pprint(parse_smtp(data_payload))