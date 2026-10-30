import itertools
import random

import pytest

from src.engine.content_matcher import find, is_relative, match_chain, relative_window
from src.models.rule import ContentSpec
from src.rules.validator import parse_rule


def contents_of(options):
    result = parse_rule(f'alert tcp any any -> any any (msg:"x"; {options} sid:1;)')
    assert result.status == "valid", result
    return result.rule.contents


def chain(payload, options):
    return match_chain(payload, contents_of(options))


# --- T11: hand-computed ---------------------------------------------------------------------------------------

T11 = b"AAA-BBB-CCC-BBB"        # 15 bytes


def test_t11_row1_window_after_first_content():
    # AAA ends at 3 -> window [4,7) -> BBB at 4
    assert chain(T11, 'content:"AAA"; content:"BBB"; distance:1; within:3;') == [(0, 3), (4, 3)]


def test_t11_row2_content_outside_the_window():
    # window [4,7); CCC is at 8
    assert chain(T11, 'content:"AAA"; content:"CCC"; distance:1; within:3;') is None


def test_t11_row3_second_bbb_searched_after_the_first_one_ended():
    # first BBB at 4 ends at 7 -> search from 8 -> BBB at 12
    assert chain(T11, 'content:"BBB"; content:"BBB"; distance:1;') == [(4, 3), (12, 3)]


def test_backtracking_case():
    payload = b"BBB----BBB-CCC"             # 14 bytes
    options = 'content:"BBB"; content:"CCC"; distance:1; within:3;'
    # BBB at 0 -> window [4,7) holds no CCC -> try BBB at 7 (ends 10) -> window [11,14) -> CCC at 11
    assert chain(payload, options) == [(7, 3), (11, 3)]


def test_without_backtracking_the_first_choice_would_wrongly_fail():
    payload = b"BBB----BBB-CCC"
    ccc = contents_of('content:"BBB"; content:"CCC"; distance:1; within:3;')[1]
    # the first BBB (0..3) gives the window [4,7): no CCC there, so a matcher that never goes back fails
    start, end = relative_window(ccc, 3)
    assert (start, end) == (4, 7) and find(payload, b"CCC", False, start, end) == -1
    # the whole chain still matches, through the second BBB
    assert match_chain(payload, contents_of('content:"BBB"; content:"CCC"; distance:1; within:3;')) is not None


# --- window arithmetic ------------------------------------------------------------------------------------------------

@pytest.mark.parametrize("spec, prev_end, expected", [
    (ContentSpec("A", b"A", distance=1, within=3), 3, (4, 7)),
    (ContentSpec("A", b"A", distance=0), 3, (3, None)),
    (ContentSpec("A", b"A", within=5), 3, (3, 8)),
    (ContentSpec("A", b"A", distance=-2, within=4), 5, (3, 7)),
    (ContentSpec("A", b"A", distance=-10, within=4), 5, (0, 4)),         # clamped to 0
    (ContentSpec("A", b"A", distance=-10), 0, (0, None)),
    (ContentSpec("A", b"A", distance=2, within=1), 0, (2, 3)),           # first content: prev_end = 0
])
def test_relative_window(spec, prev_end, expected):
    assert relative_window(spec, prev_end) == expected


def test_negative_distance_reaches_back_into_the_previous_match():
    # "ABC" ends at 3; distance:-2 -> start 1, so "BC" at 1 overlaps the previous match
    assert chain(b"ABCDEF", 'content:"ABC"; content:"BC"; distance:-2;') == [(0, 3), (1, 2)]
    assert chain(b"ABCDEF", 'content:"ABC"; content:"BC"; distance:-1;') is None      # start 2: no BC after


def test_within_alone_starts_at_the_end_of_the_previous_match():
    assert chain(b"ABxxCD", 'content:"AB"; content:"CD"; within:4;') == [(0, 2), (4, 2)]
    assert chain(b"ABxxCD", 'content:"AB"; content:"CD"; within:3;') is None


def test_first_content_with_distance_counts_from_zero():
    assert chain(b"xxxAB", 'content:"AB"; distance:3;') == [(3, 2)]
    assert chain(b"xxxAB", 'content:"AB"; distance:4;') is None
    assert chain(b"ABxxx", 'content:"AB"; distance:0; within:2;') == [(0, 2)]


def test_pattern_must_fit_entirely_inside_within():
    # AB ends at 2; distance:1 -> window starts at 3; CDE sits at 4..7
    assert chain(b"AB-xCDE", 'content:"AB"; content:"CDE"; distance:1; within:4;') == [(0, 2), (4, 3)]
    assert chain(b"AB-xCDE", 'content:"AB"; content:"CDE"; distance:1; within:3;') is None      # window [3,6) cuts it


# --- absolute contents inside a chain ------------------------------------------------------------------------------------

def test_absolute_content_ignores_the_previous_match_but_feeds_the_next_relative_one():
    # "ZZ" is searched in its own [0,3) window; "YY" follows from the end of ZZ's match
    assert chain(b"ZZ-YY", 'content:"ZZ"; offset:0; depth:3; content:"YY"; distance:1; within:2;') == [(0, 2), (3, 2)]
    # a LATER absolute content is not pushed by prev_end
    assert chain(b"ABCDEFGH", 'content:"GH"; content:"AB"; offset:0; depth:2;') == [(6, 2), (0, 2)]


def test_nocase_is_per_content():
    assert chain(b"abcDEF", 'content:"ABC"; nocase; content:"DEF"; distance:0;') == [(0, 3), (3, 3)]
    assert chain(b"abcDEF", 'content:"ABC"; nocase; content:"def"; distance:0;') is None
    assert chain(b"abcDEF", 'content:"abc"; content:"def"; nocase; distance:0;') == [(0, 3), (3, 3)]


def test_lowered_is_computed_only_when_some_content_needs_it():
    class Counting(bytes):
        calls = 0

        def lower(self):
            Counting.calls += 1
            return bytes.lower(self)

    payload = Counting(b"abcDEF")
    match_chain(payload, contents_of('content:"abc"; content:"DEF"; distance:0;'))
    assert Counting.calls == 0
    match_chain(payload, contents_of('content:"ABC"; nocase; content:"DEF"; distance:0;'))
    assert Counting.calls == 1                      # once for the whole rule, not once per content


# --- edges ---------------------------------------------------------------------------------------------------------------------------

def test_rule_without_content_is_vacuously_true():
    assert match_chain(b"anything", ()) == []
    assert match_chain(None, ()) == []


@pytest.mark.parametrize("payload", [None, b"", "text", 5])
def test_no_payload_means_no_match_for_a_rule_with_content(payload):
    assert match_chain(payload, contents_of('content:"A";')) is None


def test_single_content_equals_plain_find():
    assert chain(b"xxAByy", 'content:"AB";') == [(2, 2)]
    assert chain(b"xxAByy", 'content:"AB"; offset:3;') is None


def test_is_relative_decides_the_search_mode():
    first, second = contents_of('content:"A"; content:"B"; distance:0;')
    assert not is_relative(first) and is_relative(second)


def test_pathological_payload_stays_fast():
    # without remembering failed (content, prev_end) pairs this would explore ~n**k paths
    payload = b"A" * 400
    options = ('content:"A"; content:"A"; distance:0; content:"A"; distance:0; content:"A"; distance:0; '
               'content:"A"; distance:0; content:"B"; distance:0;')
    assert chain(payload, options) is None


def test_absolute_content_states_are_shared_whatever_the_previous_end():
    # content 0 matches at many places (prev_end differs), content 2 is absolute and never matches:
    # it must fail once, not once per prev_end -- observable as speed on a long payload
    payload = b"A" * 1000
    options = 'content:"A"; content:"A"; distance:0; content:"B"; offset:0; depth:5; content:"C"; distance:0;'
    assert chain(payload, options) is None


# --- cross-check against a different, brute-force implementation ------------------------------------------------------------------

def reference_match(payload, contents):
    """Exhaustive: try EVERY combination of occurrence positions; written independently of match_chain."""
    low = payload.lower()

    def occurrences(spec):
        pat = spec.pattern.lower() if spec.nocase else spec.pattern
        hay = low if spec.nocase else payload
        return [p for p in range(len(payload) - len(pat) + 1) if hay[p:p + len(pat)] == pat]

    def ok(combo):
        prev_end = 0
        for spec, pos in zip(contents, combo):
            end_pos = pos + len(spec.pattern)
            if spec.distance is not None or spec.within is not None:
                lo = max(0, prev_end + (spec.distance or 0))
                hi = len(payload) if spec.within is None else lo + spec.within
            else:
                lo = spec.offset or 0
                hi = len(payload) if spec.depth is None else lo + spec.depth
            if pos < lo or end_pos > hi:
                return False
            prev_end = end_pos
        return True

    return any(ok(c) for c in itertools.product(*[occurrences(s) for s in contents]))


def random_content(rng):
    pattern = rng.choice([b"A", b"B", b"AB", b"BA", b"AA", b"ABA", b"a", b"b", b"Ab"])
    nocase = rng.random() < 0.3
    relative = rng.random() < 0.7
    kw = {"nocase": nocase}
    if relative:
        if rng.random() < 0.7:
            kw["distance"] = rng.randint(-3, 4)
        if rng.random() < 0.7 or "distance" not in kw:
            kw["within"] = rng.randint(1, 8)
    else:
        if rng.random() < 0.5:
            kw["offset"] = rng.randint(0, 6)
        if rng.random() < 0.5:
            kw["depth"] = rng.randint(1, 10)
    return ContentSpec(pattern.decode(), pattern, **kw)


def test_agrees_with_brute_force_on_random_cases():
    rng = random.Random(20260430)
    checked = matched = 0
    for _ in range(4000):
        payload = bytes(rng.choice(b"ABab-") for _ in range(rng.randint(0, 14)))
        contents = tuple(random_content(rng) for _ in range(rng.randint(1, 4)))
        got = match_chain(payload, contents)
        assert (got is not None) == reference_match(payload, contents), (payload, contents, got)
        if got is not None:
            matched += 1
            for spec, (pos, length) in zip(contents, got):          # the reported positions really match
                piece = payload[pos:pos + length]
                assert (piece.lower() == spec.pattern.lower()) if spec.nocase else piece == spec.pattern
        checked += 1
    assert checked == 4000 and 300 < matched < 3700          # both outcomes are well covered
