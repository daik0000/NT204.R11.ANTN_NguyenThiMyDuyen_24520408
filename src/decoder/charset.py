import codecs
import re
from typing import Tuple, Dict, Any, Optional

# Python codec name (as returned by codecs.lookup) -> label stored in info["charset"].
# Only these character sets are accepted; aliases such as "utf8", "ascii" or "latin1" resolve to them.
SUPPORTED_CHARSETS = {
    "utf-8": "utf-8",
    "ascii": "us-ascii",
    "iso8859-1": "iso-8859-1",
}

# A payload is treated as binary when at least this share of its bytes are NUL.
# A single stray NUL inside otherwise textual data must NOT hide the invalid-bytes signal (Test T04).
BINARY_NUL_RATIO = 0.30

# Maximum length of an unsupported charset name copied into the log (it is attacker-controlled).
MAX_HINT_LOG_LEN = 64

# With errors="surrogateescape" every undecodable byte becomes exactly one lone surrogate (U+DC80..U+DCFF).
# This gives an exact per-byte count that cannot be confused with a legitimate U+FFFD in the data.
_ESCAPED_BYTE_RE = re.compile("[\udc80-\udcff]")


def _resolve_charset(hint: str) -> Optional[Tuple[str, str]]:
    """Returns (python_codec_name, label) for a supported charset hint, or None if unsupported."""
    try:
        codec_name = codecs.lookup(hint.strip().strip("\"'").lower()).name
    except (LookupError, ValueError):
        return None
    label = SUPPORTED_CHARSETS.get(codec_name)
    return (codec_name, label) if label else None


def decode_bytes(
    data: bytes, charset_hint: Optional[str] = None, detect_binary: bool = True
) -> Tuple[str, str, Dict[str, Any]]:
    """
    Safely decodes bytes into a text string.
    
    Returns a tuple: (decoded_text, decode_status, info_dict)
    - decode_status: "OK", "PARTIAL" (if invalid bytes were replaced), or "SKIPPED" (if empty/binary).
    - info_dict for PARTIAL: invalid_byte_count (exact number of undecodable BYTES) and
      first_invalid_offset (byte offset of the first one).
    - detect_binary: set to False for short, attacker-controlled values (URL components) that must
      never be dropped as "binary" (e.g. a value made only of %00 bytes).
    """
    if not data:
        return "", "SKIPPED", {"reason": "empty_payload"}

    # Heuristic: DENSE NUL bytes indicate binary data (e.g., images, compiled files).
    # This prevents the decoder from trying to convert binary files into meaningless text.
    if detect_binary and data.count(b"\x00") / len(data) >= BINARY_NUL_RATIO:
        return "", "SKIPPED", {"reason": "binary_content"}

    info: Dict[str, Any] = {}
    codec_name, label = "utf-8", "utf-8"

    # Process the charset_hint (usually extracted from Content-Type header)
    if charset_hint:
        resolved = _resolve_charset(charset_hint)
        if resolved:
            codec_name, label = resolved
        else:
            # If the charset is unknown/unsupported, fallback to utf-8 but log the anomaly
            info["charset_unsupported"] = charset_hint[:MAX_HINT_LOG_LEN]

    info["charset"] = label

    # iso-8859-1 maps 1-to-1 with bytes and never raises UnicodeDecodeError.
    # We only use it if explicitly declared in the header, never as a fallback,
    # to avoid hiding actual garbage/invalid bytes.
    if codec_name == "iso8859-1":
        return data.decode("iso-8859-1"), "OK", info

    try:
        # First, attempt a strict decode
        text = data.decode(codec_name, errors="strict")
        return text, "OK", info
    except UnicodeDecodeError as e:
        # Core of Test T04: If strict decoding fails, do NOT use errors="ignore" (which silently drops bytes).
        # Decode again escaping each bad byte, count them exactly, then show them as U+FFFD.
        escaped = data.decode(codec_name, errors="surrogateescape")
        info["invalid_byte_count"] = len(_ESCAPED_BYTE_RE.findall(escaped))
        info["first_invalid_offset"] = e.start
        
        return _ESCAPED_BYTE_RE.sub("\ufffd", escaped), "PARTIAL", info