from typing import Any, Optional


def _as_bytes(payload: Any) -> Optional[bytes]:
    """The payload as bytes, or None when there is nothing searchable (None, empty, not bytes-like)."""
    if isinstance(payload, (bytes, bytearray)):
        return payload if payload else None
    if isinstance(payload, memoryview):
        return payload.tobytes() or None
    return None


def find(payload: Any, pattern: bytes, nocase: bool = False, start: int = 0,
         end: Optional[int] = None, lowered: Optional[bytes] = None) -> int:
    """
    Index of the first occurrence of `pattern` in payload[start:end], as an index into the WHOLE
    payload, or -1. Odd payloads and patterns (None, empty, not bytes-like) give -1 and never raise;
    `start` and `end` must be ints (`end` may be None), as the Parser guarantees for rule values.

    The pattern must lie completely inside the window (that is what offset/depth mean). `start`
    below 0 is taken as 0; `end` None or past the payload is taken as the payload length; an empty
    window gives -1.

    nocase compares in lower case, ASCII only: bytes.lower() changes A-Z and nothing else, which
    is Snort's behaviour (b"\\xc3\\x89" and b"\\xc3\\xa9" stay different). Lower-casing the payload
    costs O(n), so a rule with several contents should do it once and pass the result as `lowered`
    (it must be payload.lower(); only its length is checked, and it is only read when nocase is True).
    Without it, the payload is lower-cased on every call. A caller should compute it only for rules
    that have a nocase content, and should pass bytes: a memoryview is copied on every call.

    No payload (None, empty, not bytes-like) or an empty pattern gives -1.
    """
    data = _as_bytes(payload)
    if data is None or not isinstance(pattern, (bytes, bytearray)) or not pattern:
        return -1

    start = max(0, start)
    stop = len(data) if end is None else min(end, len(data))
    if start >= stop or len(pattern) > stop - start:
        return -1

    if nocase:
        if lowered is None or len(lowered) != len(data):
            lowered = data.lower()
        return lowered.find(bytes(pattern).lower(), start, stop)
    return data.find(bytes(pattern), start, stop)
