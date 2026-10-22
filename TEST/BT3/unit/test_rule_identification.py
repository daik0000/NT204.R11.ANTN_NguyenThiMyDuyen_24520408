import pytest

from src.models.rule_report import is_valid_reason
from src.rules.parser import (
    IDENTIFICATION_KEYWORDS, MATCH_KEYWORDS, PASSIVE_KEYWORDS, SUPPORTED_KEYWORDS, RuleSyntaxError,
    parse_identification, tokenize_rule, unquote_string, unsupported_keyword,
)

HEAD = "alert tcp any any -> any 80"
BS = chr(92)


def _opts(body):
    return tokenize_rule(f"{HEAD} ({body})")[1]


def _ident(body, default_priority=3):
    return parse_identification(_opts(body), default_priority)


def _reason(body):
    with pytest.raises(RuleSyntaxError) as exc:
        _ident(body)
    assert is_valid_reason(exc.value.reason)
    return exc.value.reason


def test_basic():
    i = _ident('msg:"WEB attack"; sid:1000001; rev:3; classtype:web-application-attack; priority:2;')
    assert (i.msg, i.sid, i.rev, i.classtype, i.priority) == ("WEB attack", 1000001, 3, "web-application-attack", 2)
    assert i.passive_options == ()


def test_defaults():
    i = _ident('msg:"x"; sid:1;', default_priority=5)
    assert (i.rev, i.classtype, i.priority) == (1, None, 5)


def test_msg_unescape():
    assert _ident('msg:"a' + BS + ';b"; sid:1;').msg == "a;b"
    assert _ident('msg:"say ' + BS + '"hi' + BS + '""; sid:1;').msg == 'say "hi"'
    assert _ident('msg:"back' + BS * 2 + 'slash"; sid:1;').msg == "back" + BS + "slash"
    assert _ident('msg:"keep ' + BS + 'n"; sid:1;').msg == "keep " + BS + "n"
    assert _ident('msg:"a;b:c"; sid:1;').msg == "a;b:c"
    assert _ident('msg:""; sid:1;').msg == ""


@pytest.mark.parametrize("body", [
    "msg:hello; sid:1;", "msg; sid:1;", 'msg:"a" x; sid:1;', 'msg:"a""b"; sid:1;',
    'msg:x"y"; sid:1;', "sid:1;",
])
def test_missing_or_badly_quoted_msg(body):
    assert _reason(body) == "invalid:missing_msg"


@pytest.mark.parametrize("body", [
    'msg:"x; sid:1;', 'msg:"a"b"; sid:1;', 'msg:x"; sid:1;', 'msg:"a' + BS + '"; sid:1;',
])
def test_unbalanced_quotes_are_rejected_by_the_tokenizer(body):
    with pytest.raises(RuleSyntaxError) as exc:
        _opts(body)
    assert exc.value.reason == "invalid:malformed_rule"


def test_unquote_string_direct():
    assert unquote_string(None) is None
    assert unquote_string('"') is None
    assert unquote_string("abc") is None
    assert unquote_string('"abc"') == "abc"


@pytest.mark.parametrize("sid", ["0", "-1", "+5", "abc", "1.5", "", "٣", "1 2", "4294967296", "9" * 5000])
def test_bad_sid(sid):
    assert _reason(f'msg:"x"; sid:{sid};') == "invalid:bad_sid"


def test_sid_upper_bound_is_accepted():
    assert _ident('msg:"x"; sid:4294967295;').sid == 4294967295


@pytest.mark.parametrize("key", ["rev", "priority"])
@pytest.mark.parametrize("val", ["4294967296", "9" * 5000])
def test_huge_rev_priority_rejected_without_crash(key, val):
    assert _reason(f'msg:"x"; sid:1; {key}:{val};') == f"invalid:bad_option_value:{key}"


def test_bare_sid_keyword_is_bad_sid():
    assert _reason('msg:"x"; sid;') == "invalid:bad_sid"


def test_missing_sid():
    assert _reason('msg:"x";') == "invalid:missing_sid"
    assert _reason("") == "invalid:missing_sid"


def test_missing_sid_reported_before_missing_msg():
    assert _reason("rev:1;") == "invalid:missing_sid"


def test_value_errors_reported_before_missing():
    assert _reason('msg:"x"; rev:0;') == "invalid:bad_option_value:rev"


@pytest.mark.parametrize("key", ["sid", "msg", "rev", "classtype", "priority"])
def test_duplicate_option(key):
    values = {"sid": "1", "msg": '"x"', "rev": "1", "classtype": "a", "priority": "1"}
    body = f'msg:"x"; sid:1; {key}:{values[key]}; {key}:{values[key]};'
    if key in ("msg", "sid"):
        body = f'msg:"x"; sid:1; {key}:{values[key]};'
    assert _reason(body) == f"invalid:duplicate_option:{key}"


@pytest.mark.parametrize("key, val", [
    ("rev", "0"), ("rev", "-1"), ("rev", "x"), ("rev", ""), ("priority", "0"), ("priority", "1.5"),
    ("priority", "abc"), ("classtype", ""), ("classtype", "a b"), ("classtype", '"quoted"'),
])
def test_bad_option_values(key, val):
    assert _reason(f'msg:"x"; sid:1; {key}:{val};') == f"invalid:bad_option_value:{key}"


def test_bare_rev_priority_classtype_are_bad_values():
    for key in ("rev", "priority", "classtype"):
        assert _reason(f'msg:"x"; sid:1; {key};') == f"invalid:bad_option_value:{key}"


def test_passive_options_stored_and_may_repeat():
    i = _ident('msg:"x"; sid:1; reference:cve,2020-1; reference:url,example.com; metadata:a b; gid:1;')
    assert i.passive_options == (
        ("reference", "cve,2020-1"), ("reference", "url,example.com"), ("metadata", "a b"), ("gid", "1"),
    )


def test_first_problem_in_rule_order_wins():
    assert _reason('sid:0; rev:0;') == "invalid:bad_sid"
    assert _reason('rev:0; sid:0;') == "invalid:bad_option_value:rev"


def test_match_and_unknown_keywords_ignored_here():
    i = _ident('msg:"x"; sid:1; content:"a"; nocase; pcre:"/a/"; flow:to_server;')
    assert i.sid == 1


# --- keyword whitelist ---------------------------------------------------------------------

def test_keyword_sets_are_disjoint_and_complete():
    sets = [set(IDENTIFICATION_KEYWORDS), set(PASSIVE_KEYWORDS), set(MATCH_KEYWORDS)]
    assert sum(len(s) for s in sets) == len(set().union(*sets)) == len(SUPPORTED_KEYWORDS)
    assert set(PASSIVE_KEYWORDS) == {"reference", "metadata", "gid"}
    assert "pcre" not in SUPPORTED_KEYWORDS


@pytest.mark.parametrize("kw", [
    "pcre", "byte_test", "byte_jump", "flowbits", "threshold", "http_uri", "fast_pattern",
    "isdataat", "ack", "seq", "ttl", "SID", "Content", "detection_filter", "sameip",
])
def test_unsupported_keyword(kw):
    reason = unsupported_keyword(_opts(f'msg:"x"; sid:1; {kw}:1;'))
    assert reason == f"unsupported:keyword:{kw}" and is_valid_reason(reason)


def test_unsupported_keyword_bare_form():
    assert unsupported_keyword(_opts('msg:"x"; sid:1; fast_pattern;')) == "unsupported:keyword:fast_pattern"


def test_unsupported_keyword_none_when_all_supported():
    body = ('msg:"x"; sid:1; rev:1; classtype:a; priority:1; reference:a,b; metadata:x; gid:1; '
            'content:"a"; nocase; offset:0; depth:5; distance:1; within:5; flow:to_server; flags:S; dsize:>1;')
    assert unsupported_keyword(_opts(body)) is None


def test_first_unsupported_keyword_reported():
    assert unsupported_keyword(_opts("sid:1; pcre:1; ttl:1;")) == "unsupported:keyword:pcre"
