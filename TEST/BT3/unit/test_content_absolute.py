import pytest

from src.engine.content_matcher import absolute_window, find_absolute, is_relative
from src.models.rule import ContentSpec
from src.rules.validator import parse_rule

T10_PAYLOAD = b"ABCDEFGHIJ"        # 10 bytes


def content_spec(options):
    """The first ContentSpec the Parser builds from `content:...` options."""
    result = parse_rule(f'alert tcp any any -> any any (msg:"x"; {options} sid:1;)')
    assert result.status == "valid", result
    return result.rule.contents[0]


# --- T10: hand-computed ------------------------------------------------------------------------------------------

@pytest.mark.parametrize("options, window, expected", [
    ('content:"CD"; offset:2; depth:2;', (2, 4), 2),
    ('content:"CD"; offset:3;', (3, None), -1),
    ('content:"CD"; depth:3;', (0, 3), -1),
    ('content:"CD"; depth:4;', (0, 4), 2),
    ('content:"J"; offset:9;', (9, None), 9),
    ('content:"J"; offset:10;', (10, None), -1),
])
def test_t10(options, window, expected):
    spec = content_spec(options)
    assert absolute_window(spec) == window
    assert find_absolute(T10_PAYLOAD, spec) == expected


def test_depth_is_a_window_size_not_a_position():
    # if depth were an absolute position, offset:2; depth:2 would be the empty window [2, 2)
    spec = content_spec('content:"CD"; offset:2; depth:2;')
    assert absolute_window(spec) == (2, 4)
    assert find_absolute(T10_PAYLOAD, spec) == 2
    far = content_spec('content:"HI"; offset:7; depth:2;')
    assert absolute_window(far) == (7, 9) and find_absolute(T10_PAYLOAD, far) == 7


def test_offset_beyond_the_payload_is_an_empty_window_not_an_error():
    for options in ('content:"A"; offset:10;', 'content:"A"; offset:11;', 'content:"A"; offset:4000000000;'):
        assert find_absolute(T10_PAYLOAD, content_spec(options)) == -1


def test_no_constraints_searches_everything():
    spec = content_spec('content:"J";')
    assert absolute_window(spec) == (0, None)
    assert find_absolute(T10_PAYLOAD, spec) == 9


def test_pattern_must_fit_entirely_inside_the_depth_window():
    assert find_absolute(T10_PAYLOAD, content_spec('content:"CDE"; depth:4;')) == -1      # CDE ends at 5
    assert find_absolute(T10_PAYLOAD, content_spec('content:"CDE"; depth:5;')) == 2


def test_offset_alone_and_depth_alone_and_both():
    assert find_absolute(T10_PAYLOAD, content_spec('content:"AB"; offset:0;')) == 0
    assert find_absolute(T10_PAYLOAD, content_spec('content:"IJ"; offset:8;')) == 8
    assert find_absolute(T10_PAYLOAD, content_spec('content:"IJ"; offset:7; depth:3;')) == 8
    assert find_absolute(T10_PAYLOAD, content_spec('content:"IJ"; offset:7; depth:2;')) == -1


def test_nocase_with_a_window():
    spec = content_spec('content:"cd"; nocase; offset:2; depth:2;')
    assert find_absolute(T10_PAYLOAD, spec) == 2
    assert find_absolute(T10_PAYLOAD, content_spec('content:"cd"; offset:2; depth:2;')) == -1


def test_lowered_is_passed_through():
    spec = content_spec('content:"cd"; nocase;')
    assert find_absolute(T10_PAYLOAD, spec, lowered=T10_PAYLOAD.lower()) == 2


def test_depth_zero_is_an_empty_window():
    spec = ContentSpec("A", b"A", depth=0)        # hand-built: the Parser rejects depth < pattern length
    assert absolute_window(spec) == (0, 0)
    assert find_absolute(T10_PAYLOAD, spec) == -1


def test_empty_or_missing_payload():
    spec = content_spec('content:"A"; offset:0;')
    assert find_absolute(b"", spec) == -1 and find_absolute(None, spec) == -1


def test_window_of_a_content_with_relative_modifiers_ignores_them():
    spec = content_spec('content:"A"; content:"CD"; distance:0; within:2;')   # first content has no modifiers
    assert absolute_window(spec) == (0, None)
    relative = ContentSpec("CD", b"CD", distance=1, within=5)
    assert absolute_window(relative) == (0, None)         # distance/within are not applied here


def test_depth_longer_than_the_payload_is_cut_at_its_end():
    spec = content_spec('content:"IJ"; depth:1000;')
    assert absolute_window(spec) == (0, 1000)
    assert find_absolute(T10_PAYLOAD, spec) == find_absolute(T10_PAYLOAD, content_spec('content:"IJ";')) == 8
    assert find_absolute(T10_PAYLOAD, content_spec('content:"IJ"; offset:5; depth:1000;')) == 8
    assert find_absolute(T10_PAYLOAD, content_spec('content:"K"; depth:1000;')) == -1


def test_explicit_offset_zero_is_the_same_as_no_offset():
    plain, zero = content_spec('content:"CD";'), content_spec('content:"CD"; offset:0;')
    assert absolute_window(plain) == absolute_window(zero) == (0, None)
    assert find_absolute(T10_PAYLOAD, plain) == find_absolute(T10_PAYLOAD, zero) == 2
    assert absolute_window(content_spec('content:"CD"; offset:0; depth:4;')) == (0, 4)


def test_is_relative_classifies_every_content():
    assert is_relative(content_spec('content:"A";')) is False
    assert is_relative(content_spec('content:"A"; offset:2; depth:5; nocase;')) is False
    assert is_relative(content_spec('content:"A"; distance:0;')) is True
    assert is_relative(content_spec('content:"A"; within:5;')) is True
    assert is_relative(content_spec('content:"A"; distance:-2; within:9;')) is True
    assert is_relative(ContentSpec("A", b"A", distance=0)) is True


def test_a_relative_content_would_be_searched_everywhere_if_sent_to_find_absolute():
    # why is_relative must be checked first: find_absolute ignores distance/within
    spec = ContentSpec("J", b"J", distance=100, within=1)
    assert is_relative(spec) is True
    assert find_absolute(T10_PAYLOAD, spec) == 9
