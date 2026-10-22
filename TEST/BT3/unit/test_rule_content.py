import pytest

from src.models.rule_report import is_valid_reason
from src.rules.parser import RuleSyntaxError, decode_content, parse_contents, tokenize_rule

HEAD = "alert tcp any any -> any 80"
BS = chr(92)


def _opts(body):
    return tokenize_rule(f"{HEAD} ({body})")[1]


def _contents(body):
    return parse_contents(_opts(body))


def _reason(body):
    with pytest.raises(RuleSyntaxError) as exc:
        _contents(body)
    assert is_valid_reason(exc.value.reason)
    return exc.value.reason


# --- pattern decoding (hand-computed values) -------------------------------------------------

@pytest.mark.parametrize("text, expected", [
    ('"GET"', b"GET"),
    ('"GE|54|"', b"GET"),
    ('"|47 45 54|"', b"GET"),
    ('"|41 42 7c|"', b"AB|"),
    ('"|41 42 7C|"', b"AB|"),
    ('"a' + BS + ';b"', b"a;b"),
    ('"a' + BS + '"b"', b'a"b'),
    ('"a' + BS * 2 + 'b"', b"a" + BS.encode() + b"b"),
    ('"a|7C|b"', b"a|b"),
    ('"|41|B|43|"', b"ABC"),
    ('"|4 1|"', b"A"),
    ('"|  41   42  |"', b"AB"),
    ('"|41||42|"', b"AB"),
    ('"../"', b"../"),
    ('"' + BS + 'n"', BS.encode() + b"n"),
    ('"é"', b"\xc3\xa9"),
    ('"tấn công"', "tấn công".encode("utf-8")),
    ('"' + BS + 'é"', BS.encode() + b"\xc3\xa9"),
    ('"é|e9|"', b"\xc3\xa9\xe9"),
    ('"|00 ff|"', b"\x00\xff"),
])
def test_decode_content(text, expected):
    assert decode_content(text)[1] == expected


def test_non_utf8_byte_in_rule_file_is_rejected(tmp_path):
    # the Loader turns an invalid byte into U+FFFD, so the rule cannot match by accident
    from src.rules.loader import iter_rule_lines
    f = tmp_path / "x.rules"
    f.write_bytes(b'content:"a\xffb"\n')
    (_, text), = list(iter_rule_lines(f))
    with pytest.raises(RuleSyntaxError):
        decode_content(text.split(":", 1)[1])


def test_decode_keeps_raw_text():
    assert decode_content('"GE|54|"')[0] == "GE|54|"


def test_semicolon_in_content_via_tokenizer():
    c = _contents('content:"a' + BS + ';b"; sid:1;')
    assert c[0].pattern == b"a;b"


@pytest.mark.parametrize("text", [
    '"|4|"', '"|414|"', '"|4g|"', '"|41"', '"41|"', '"|41 4|"', '""', '"||"', '"|  |"',
    "abc", "", None, '"abc', 'abc"', '"a"b"', '"\ufffd"', '"a\ufffdb"', '"' + BS + '\ufffd"', '"|41' + BS + '|"', '"a' + BS + '"',
])
def test_decode_content_bad(text):
    with pytest.raises(RuleSyntaxError) as exc:
        decode_content(text)
    assert exc.value.reason == "invalid:bad_option_value:content"


def test_decode_negation_is_unsupported():
    with pytest.raises(RuleSyntaxError) as exc:
        decode_content('!"abc"')
    assert exc.value.reason == "unsupported:content_negation"


def test_bare_content_keyword_is_bad_value():
    assert _reason("content; sid:1;") == "invalid:bad_option_value:content"


# --- modifiers ---------------------------------------------------------------------------------

def test_defaults_and_order_preserved():
    c = _contents('content:"a"; content:"b"; content:"c"; sid:1;')
    assert [x.pattern for x in c] == [b"a", b"b", b"c"]
    assert (c[0].nocase, c[0].offset, c[0].depth, c[0].distance, c[0].within) == (False, None, None, None, None)


def test_modifiers_attach_to_preceding_content():
    c = _contents('content:"a"; nocase; offset:2; depth:10; content:"b"; distance:-3; within:5; sid:1;')
    assert (c[0].nocase, c[0].offset, c[0].depth, c[0].distance, c[0].within) == (True, 2, 10, None, None)
    assert (c[1].nocase, c[1].offset, c[1].depth, c[1].distance, c[1].within) == (False, None, None, -3, 5)


@pytest.mark.parametrize("value, expected", [("0", 0), ("7", 7), ("-1", -1), ("-0", 0), ("4294967295", 4294967295)])
def test_distance_values(value, expected):
    assert _contents(f'content:"a"; distance:{value}; sid:1;')[0].distance == expected


@pytest.mark.parametrize("key, value", [
    ("offset", "-1"), ("offset", "x"), ("offset", ""), ("offset", "1.5"), ("offset", "+1"),
    ("depth", "-1"), ("depth", "abc"), ("depth", "4294967296"), ("depth", "9" * 5000),
    ("within", "0"), ("within", "-1"), ("within", "x"),
    ("distance", "x"), ("distance", "--1"), ("distance", "-"), ("distance", "+1"), ("distance", ""),
    ("distance", "-" + "9" * 5000),
])
def test_bad_modifier_values(key, value):
    assert _reason(f'content:"a"; {key}:{value}; sid:1;') == f"invalid:bad_option_value:{key}"


@pytest.mark.parametrize("key", ["offset", "depth", "within", "distance"])
def test_bare_modifier_needs_value(key):
    assert _reason(f'content:"a"; {key}; sid:1;') == f"invalid:bad_option_value:{key}"


def test_nocase_takes_no_value():
    assert _reason('content:"a"; nocase:1; sid:1;') == "invalid:bad_option_value:nocase"


def test_within_one_and_offset_zero_ok():
    c = _contents('content:"a"; within:1; offset:0; depth:0; sid:1;')[0]
    assert (c.within, c.offset, c.depth) == (1, 0, 0)


@pytest.mark.parametrize("mod", ["nocase", "offset:1", "depth:1", "distance:1", "within:1"])
def test_modifier_without_content(mod):
    assert _reason(f'{mod}; content:"a"; sid:1;') == "invalid:modifier_without_content"


def test_modifier_before_content_even_when_later_content_exists():
    assert _reason('sid:1; nocase;') == "invalid:modifier_without_content"


@pytest.mark.parametrize("mod", ["nocase", "offset:1", "depth:1", "distance:1", "within:1"])
def test_duplicate_modifier_on_same_content(mod):
    key = mod.split(":")[0]
    assert _reason(f'content:"a"; {mod}; {mod}; sid:1;') == f"invalid:duplicate_option:{key}"


def test_same_modifier_on_different_contents_is_fine():
    c = _contents('content:"a"; nocase; content:"b"; nocase; sid:1;')
    assert [x.nocase for x in c] == [True, True]


def test_no_content_gives_empty_tuple():
    assert _contents('msg:"x"; sid:1;') == ()


def test_other_keywords_ignored():
    assert len(_contents('msg:"x"; flow:to_server; content:"a"; flags:S; sid:1;')) == 1


# --- negation ----------------------------------------------------------------------------------

def test_negated_content_is_unsupported():
    assert _reason('content:!"abc"; sid:1;') == "unsupported:content_negation"


def test_invalid_wins_over_negation():
    assert _reason('content:!"abc"; offset:x; sid:1;') == "invalid:bad_option_value:offset"
    assert _reason('content:!"abc"; content:"|4|"; sid:1;') == "invalid:bad_option_value:content"
    assert _reason('content:!"abc"; nocase; nocase; sid:1;') == "invalid:duplicate_option:nocase"


def test_modifier_after_negated_content_is_not_orphaned():
    assert _reason('content:!"abc"; nocase; sid:1;') == "unsupported:content_negation"


def test_negated_content_is_not_returned_but_error_wins():
    assert _reason('content:"ok"; content:!"bad"; sid:1;') == "unsupported:content_negation"
