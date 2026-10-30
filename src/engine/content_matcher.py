from typing import Any, Optional, Tuple

from src.models.rule import ContentSpec


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


def is_relative(spec: ContentSpec) -> bool:
    """
    True if the content is positioned relative to the previous match (it has distance or within).

    The caller MUST classify every content with this before searching: find_absolute ignores
    distance/within, so sending a relative content there would silently search the whole payload.
    """
    return spec.distance is not None or spec.within is not None


def absolute_window(spec: ContentSpec) -> Tuple[int, Optional[int]]:
    """
    (start, end) of the search window of a content that is not relative, as `find` takes them.

    start is `offset` (0 when absent). `depth` is the SIZE of the window counted from start, not an
    absolute position: end = start + depth. Without depth, end is None (up to the end of the
    payload). So offset:2; depth:2 is [2, 4), and depth:3 alone is [0, 3).
    """
    start = spec.offset or 0
    end = None if spec.depth is None else start + spec.depth
    return start, end


def find_absolute(payload: Any, spec: ContentSpec, lowered: Optional[bytes] = None) -> int:
    """
    Where the content `spec` matches inside its absolute offset/depth window, or -1. Never raises.

    Only offset and depth are applied. distance and within (a window relative to the previous
    content) are handled separately; the Parser does not allow a content to carry both kinds, and
    the caller must send a content here only when is_relative(spec) is False. An offset beyond the
    payload gives an empty window, so -1; a depth that reaches past the payload is cut at its end.
    """
    start, end = absolute_window(spec)
    return find(payload, spec.pattern, spec.nocase, start, end, lowered)
