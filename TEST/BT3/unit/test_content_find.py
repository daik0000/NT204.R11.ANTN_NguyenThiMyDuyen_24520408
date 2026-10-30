import pytest

from src.engine.content_matcher import find
from src.rules.parser import decode_content

PAYLOAD = b"GET /Admin HTTP/1.1"


def pat(text):
    """The bytes the Parser builds for content:"<text>" """
    return decode_content(f'"{text}"')[1]


# --- T09: hand-computed ------------------------------------------------------------------------------------

@pytest.mark.parametrize("text, nocase, expected", [
    ("admin", False, -1),            # case matters by default
    ("admin", True, 5),              # content:"admin"; nocase;
    ("Admin", False, 5),
    ("ADMIN", True, 5),
    ("|47 45 54|", False, 0),        # GET as hex
    ("GE|54|", False, 0),            # mixed text and hex
    ("get", False, -1),
    ("get", True, 0),
    ("HTTP/1.1", False, 11),
    ("http/1.1", True, 11),
])
def test_t09(text, nocase, expected):
    assert find(PAYLOAD, pat(text), nocase) == expected


def test_position_is_where_the_pattern_starts():
    assert PAYLOAD.index(b"Admin") == 5
    assert find(PAYLOAD, b"Admin") == 5
    assert find(b"aaa", b"a") == 0


def test_first_occurrence_is_returned():
    assert find(b"abcabc", b"bc") == 1
    assert find(b"abcabc", b"bc", start=2) == 4


# --- window: start / end ---------------------------------------------------------------------------------------------

@pytest.mark.parametrize("start, end, expected", [
    (0, None, 5), (5, None, 5), (6, None, -1),            # start after the match start
    (0, 10, 5), (0, 9, -1), (0, 5, -1),                   # end cuts the pattern (Admin is 5..10)
    (5, 10, 5),                                           # exactly the window
    (2, 8, -1), (0, 100, 5),                              # end past the payload is clamped
    (-5, None, 5),                                        # negative start is 0
    (10, 10, -1), (12, 5, -1), (0, 0, -1),                # empty / inverted window
    (0, -1, -1),
])
def test_window(start, end, expected):
    assert find(PAYLOAD, b"Admin", start=start, end=end) == expected


def test_pattern_must_fit_inside_the_window_not_just_start_there():
    assert find(b"xxABCDyy", b"ABCD", start=2, end=5) == -1
    assert find(b"xxABCDyy", b"ABCD", start=2, end=6) == 2


def test_pattern_longer_than_payload_or_window():
    assert find(b"abc", b"abcd") == -1
    assert find(b"abcdef", b"abcd", start=0, end=3) == -1


# --- nocase is ASCII-only -----------------------------------------------------------------------------------------------

def test_nocase_only_changes_ascii_letters():
    assert find(b"\xc3\x89", b"\xc3\xa9", nocase=True) == -1        # E-acute vs e-acute in UTF-8
    assert find(b"\xc3\x89", b"\xc3\x89", nocase=True) == 0
    assert find(b"ABC\xc3\x89", b"abc\xc3\x89", nocase=True) == 0
    assert find(b"\xff\xfe", b"\xff\xfe", nocase=True) == 0


def test_nocase_with_binary_and_digits():
    assert find(b"\x00A1b\x00", b"a1B", nocase=True) == 1
    assert find(b"A1B", b"a1b", nocase=False) == -1


def test_nocase_respects_the_window():
    assert find(PAYLOAD, b"ADMIN", nocase=True, start=0, end=9) == -1
    assert find(PAYLOAD, b"ADMIN", nocase=True, start=5, end=10) == 5


def test_case_sensitive_search_is_not_affected_by_lowered():
    assert find(PAYLOAD, b"admin", nocase=False, lowered=PAYLOAD.lower()) == -1


# --- lowered: computed once per rule ---------------------------------------------------------------------------------------

def test_lowered_is_used_instead_of_lowering_again():
    class Counting(bytes):
        calls = 0

        def lower(self):
            Counting.calls += 1
            return bytes.lower(self)

    payload = Counting(PAYLOAD)
    lowered = payload.lower()
    assert Counting.calls == 1
    for _ in range(5):
        assert find(payload, b"ADMIN", nocase=True, lowered=lowered) == 5
    assert Counting.calls == 1                       # never lowered again
    assert find(payload, b"ADMIN", nocase=True) == 5
    assert Counting.calls == 2                       # without `lowered`, once per call


def test_wrong_length_lowered_is_ignored_safely():
    assert find(PAYLOAD, b"ADMIN", nocase=True, lowered=b"short") == 5


def test_lowered_is_not_read_when_nocase_is_false():
    assert find(PAYLOAD, b"Admin", nocase=False, lowered=b"garbage") == 5


# --- nothing to search --------------------------------------------------------------------------------------------------------------

@pytest.mark.parametrize("payload", [None, b"", bytearray(), memoryview(b""), "text", 5, [b"a"]])
def test_no_payload_gives_minus_one(payload):
    assert find(payload, b"a") == -1
    assert find(payload, b"a", nocase=True) == -1


@pytest.mark.parametrize("pattern", [b"", None, "a", 5])
def test_bad_pattern_gives_minus_one(pattern):
    assert find(PAYLOAD, pattern) == -1


def test_bytearray_and_memoryview_payloads():
    assert find(bytearray(PAYLOAD), b"Admin") == 5
    assert find(memoryview(PAYLOAD), b"Admin") == 5
    assert find(bytearray(PAYLOAD), b"ADMIN", nocase=True) == 5
    assert find(PAYLOAD, bytearray(b"Admin")) == 5


def test_never_raises_on_odd_windows():
    assert find(PAYLOAD, b"a", start=10**9) == -1
    assert find(PAYLOAD, b"a", end=-10**9) == -1


# --- overlapping occurrences (the basis of backtracking) and window edges ----------------------------------------------------

def test_overlapping_occurrences_are_found_by_moving_start():
    assert find(b"aaa", b"aa") == 0
    assert find(b"aaa", b"aa", start=1) == 1
    assert find(b"aaa", b"aa", start=2) == -1
    assert find(b"ababab", b"abab", start=1) == 2


def test_pattern_at_the_very_end_of_the_payload():
    assert find(b"xxABC", b"ABC") == 2
    assert find(b"xxABC", b"ABC", start=2, end=5) == 2
    assert find(b"xxABC", b"ABC", end=None) == 2
    assert find(b"xxABC", b"ABC", start=3) == -1


@pytest.mark.parametrize("end, expected", [(6, -1), (7, 2), (8, 2), (9, 2)])
def test_window_end_is_exact_to_the_byte(end, expected):
    # b"ABCDy" occupies bytes 2..6, so the window must reach byte 7 (end is exclusive)
    assert find(b"xxABCDyy", b"ABCDy", start=2, end=end) == expected


def test_window_start_is_exact_to_the_byte():
    assert find(b"xxABCDyy", b"ABCD", start=2) == 2
    assert find(b"xxABCDyy", b"ABCD", start=3) == -1


def test_window_edges_with_nocase():
    assert find(b"xxAbCdyy", b"abcd", nocase=True, start=2, end=6) == 2
    assert find(b"xxAbCdyy", b"abcd", nocase=True, start=2, end=5) == -1
    assert find(b"xxAbCdyy", b"abcd", nocase=True, start=3) == -1


def test_start_after_end_and_negative_values():
    assert find(PAYLOAD, b"GET", start=5, end=2) == -1
    assert find(PAYLOAD, b"GET", start=-100, end=100) == 0
