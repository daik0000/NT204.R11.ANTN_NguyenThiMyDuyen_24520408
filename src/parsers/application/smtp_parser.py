import re
from typing import Dict, Any
from src.utils.safe import safe_parse

# Regex for parsing server responses: 3 digits, followed by a space (final) or hyphen (more to come)
SMTP_RESP_RE = re.compile(r"^(\d{3})([ -])(.*)")

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
    """
    if not raw_bytes:
        raise ValueError("Empty payload, cannot be SMTP.")

    text = raw_bytes.decode('utf-8', errors='replace')
    lines = text.splitlines()

    lines = [line.strip() for line in lines if line.strip()]
    
    if not lines:
        raise ValueError("Payload contains only whitespace/empty lines.")

    # Determine packet type (command or response) based on the first line
    first_line = lines[0]
    is_response = bool(SMTP_RESP_RE.match(first_line))
    is_command = first_line.upper().startswith(SMTP_COMMANDS)

    if not is_response and not is_command:
        raise ValueError(f"First line does not match SMTP standard: {first_line[:50]}...")

    app_fields = {
        "type": "response" if is_response else "command",
        "messages": []
    }

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
    
    # Test 1: SMTP Client Commands (Multiple commands in one packet)
    print("\n--- Valid SMTP Commands ---")
    cmd_payload = b"EHLO client.example.com\r\nMAIL FROM:\r\nRCPT TO: "
    pprint.pprint(parse_smtp(cmd_payload))
    
    # Test 2: SMTP Server Response (Multi-line response)
    print("\n--- Valid Multi-line SMTP Response ---")
    resp_payload = b"250-mail.example.com\r\n250-PIPELINING\r\n250-8BITMIME\r\n250 SMTPUTF8"
    pprint.pprint(parse_smtp(resp_payload))
    
    # Test 3: Malformed SMTP containing binary bytes
    print("\n--- Malformed/Binary Bytes Payload ---")
    malformed_payload = b"220 ESMTP Postfix\r\n\xff\xfe\x00\x00Ransomware_Garbage\r\n"
    pprint.pprint(parse_smtp(malformed_payload))

    # Test 4: Not SMTP (will be caught by the decorator)
    print("\n--- Invalid Protocol (Garbage) ---")
    garbage_payload = b"SSH-2.0-OpenSSH_8.2p1\r\n"
    pprint.pprint(parse_smtp(garbage_payload))