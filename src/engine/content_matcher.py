from typing import Any, List, Optional, Set, Tuple

from src.models.rule import ContentSpec, Rule


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


def relative_window(spec: ContentSpec, prev_end: int) -> Tuple[int, Optional[int]]:
    """
    (start, end) of the search window of a content that has distance and/or within.

    start is prev_end + distance (distance may be negative; the result is never below 0), where
    prev_end is where the previous content's match ENDED (pos + len(pattern), not where it began),
    or 0 for the first content of the rule. within is the SIZE of the window from start:
    end = start + within, or None (up to the end of the payload) without within.
    """
    start = max(0, prev_end + (spec.distance or 0))
    end = None if spec.within is None else start + spec.within
    return start, end


def match_chain(payload: Any, contents: Tuple[ContentSpec, ...],
                lowered: Optional[bytes] = None) -> Optional[List[Tuple[int, int]]]:
    """
    Match all the contents of a rule, in rule order. Returns [(position, length), ...], one pair per
    content (the first combination found), or None if the rule's contents do not all match.
    A rule without content gives []. Odd payloads give None, not an exception. The recursion is as
    deep as the number of contents, so an absurd rule with around 900 contents would raise
    RecursionError; real rules have a handful, and the engine isolates each rule anyway.

    A content that is not relative (no distance/within) is searched in its own offset/depth window,
    wherever the previous content matched. A relative content is searched in the window of
    relative_window() from the end of the previous match; the first content has prev_end = 0.

    Backtracking: a content can occur at several places, and the first one is not always the right
    one. For content i every occurrence in its window is tried in turn (the next search starts one
    byte after the previous hit, so overlapping hits count), and for each the chain continues with
    content i+1. The rule fails only when no occurrence leads to a complete chain. The outcome of
    "content i from prev_end" depends on just those two values (for an absolute content only on i,
    its window being fixed), so a failed state is remembered and never explored twice: the work
    stays polynomial, whatever the payload. A packet is at most about 1460 bytes because TCP streams
    are not reassembled, which keeps even the polynomial bound small.

    The payload is lower-cased once, and only if some content has nocase.
    """
    if not contents:
        return []
    data = _as_bytes(payload)
    if data is None:
        return None
    if lowered is None and any(c.nocase for c in contents):
        lowered = data.lower()

    failed: Set[Tuple[int, int]] = set()
    path: List[Tuple[int, int]] = []

    def search(i: int, prev_end: int) -> bool:
        if i == len(contents):
            return True
        spec = contents[i]
        relative = is_relative(spec)
        state = (i, prev_end if relative else 0)      # an absolute content ignores prev_end
        if state in failed:
            return False
        start, end = relative_window(spec, prev_end) if relative else absolute_window(spec)
        length = len(spec.pattern)
        while True:
            pos = find(data, spec.pattern, spec.nocase, start, end, lowered)
            if pos < 0:
                break
            path.append((pos, length))
            if search(i + 1, pos + length):
                return True
            path.pop()
            start = pos + 1                       # next occurrence, overlapping ones included
        failed.add(state)
        return False

    return list(path) if search(0, 0) else None


def match_contents(rule: Rule, payload: Any) -> Optional[List[dict]]:
    """
    Match all the contents of `rule` against `payload`.

    Returns None when they do not match. Otherwise one dict per content, in rule order, in the
    format of Detection.matched:

        {"keyword": "content", "value": <text as written in the rule>,
         "offset": <where the match starts in the payload>, "length": <len(pattern)>}

    offset and length come from the combination of positions that finally succeeded (after any
    backtracking), not from the first position tried. `value` is ContentSpec.raw, the text between
    the quotes in the rule file (e.g. "GE|54|"), so a log shows what the rule says even when the
    pattern has hex parts or the match differed in case under nocase.

    A rule with no content gives [] (nothing to report); match_rule never calls this for such a
    rule. The payload is converted and lower-cased at most once for the whole rule.
    """
    chain = match_chain(payload, rule.contents)
    if chain is None:
        return None
    return [{"keyword": "content", "value": spec.raw, "offset": pos, "length": length}
            for spec, (pos, length) in zip(rule.contents, chain)]


def content_fn(rule: Rule, event: Any) -> Optional[List[dict]]:
    """
    The hook for match_rule(..., content_fn=content_fn): match the rule's contents against
    event.payload (the real application bytes). Returns what match_contents returns.
    """
    return match_contents(rule, getattr(event, "payload", None))
