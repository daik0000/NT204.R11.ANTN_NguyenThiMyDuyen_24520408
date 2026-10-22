import pytest

from src.models.rule import DsizeSpec, FlagsSpec, FlowSpec
from src.models.rule_report import is_valid_reason
from src.rules.parser import (
    RuleSyntaxError, parse_dsize, parse_dsize_value, parse_flags, parse_flags_value, parse_flow,
    parse_flow_value, tokenize_rule,
)

HEAD = "alert tcp any any -> any 80"


def _opts(body):
    return tokenize_rule(f"{HEAD} ({body})")[1]


def _reason(fn, *args):
    with pytest.raises(RuleSyntaxError) as exc:
        fn(*args)
    assert is_valid_reason(exc.value.reason)
    return exc.value.reason


# --- flow --------------------------------------------------------------------------------------

@pytest.mark.parametrize("value, role, state", [
    ("to_server", "to_server", None),
    ("to_client", "to_client", None),
    ("from_client", "to_server", None),
    ("from_server", "to_client", None),
    ("established", None, "established"),
    ("not_established", None, "not_established"),
    ("to_server,established", "to_server", "established"),
    ("established,to_server", "to_server", "established"),
    ("from_server , not_established", "to_client", "not_established"),
    ("to_server,from_client", "to_server", None),
    ("to_server,to_server", "to_server", None),
    ("established,established", None, "established"),
])
def test_flow_valid(value, role, state):
    assert parse_flow_value(value) == FlowSpec(role=role, state=state)


@pytest.mark.parametrize("value", [
    "to_server,to_client", "from_client,from_server", "to_server,from_server",
    "established,not_established", "to_server,to_client,established",
])
def test_flow_conflicting(value):
    assert _reason(parse_flow_value, value) == "invalid:conflicting_flow"


@pytest.mark.parametrize("word", ["stateless", "only_stream", "no_stream", "no_frag", "from_any", "bogus"])
def test_flow_unsupported(word):
    assert _reason(parse_flow_value, f"to_server,{word}") == f"unsupported:flow_option:{word}"
    assert _reason(parse_flow_value, word) == f"unsupported:flow_option:{word}"


@pytest.mark.parametrize("value", [None, "", "  ", "to_server,", ",established", "to_server,,established", ","])
def test_flow_bad_value(value):
    assert _reason(parse_flow_value, value) == "invalid:bad_option_value:flow"


def test_flow_invalid_wins_over_unsupported():
    assert _reason(parse_flow_value, "stateless,to_server,to_client") == "invalid:conflicting_flow"
    assert _reason(parse_flow_value, "stateless,") == "invalid:bad_option_value:flow"


def test_flow_case_sensitive():
    assert _reason(parse_flow_value, "TO_SERVER") == "unsupported:flow_option:TO_SERVER"


# --- flags: one row per form ------------------------------------------------------------------

@pytest.mark.parametrize("value, mode, flags", [
    ("S", "exact", "S"),
    ("SA", "exact", "SA"),
    ("AS", "exact", "SA"),
    ("F", "exact", "F"),
    ("FSRPAUCE", "exact", "FSRPAUCE"),
    ("S+", "all", "S"),
    ("SA+", "all", "SA"),
    ("S*", "any", "S"),
    ("SA*", "any", "SA"),
    ("FR*", "any", "FR"),
    ("!S", "none", "S"),
    ("!SA", "none", "SA"),
    ("C", "exact", "C"),
    ("E+", "all", "E"),
    ("SS", "exact", "S"),
    ("0", "exact", ""),
])
def test_flags_valid(value, mode, flags):
    assert parse_flags_value(value) == FlagsSpec(mode, frozenset(flags))


@pytest.mark.parametrize("value", ["SA,12", "S,12", "S+,12", "S*,12", "!S,12", "0,12", "S,"])
def test_flags_mask_unsupported(value):
    assert _reason(parse_flags_value, value) == "unsupported:flags_mask"


@pytest.mark.parametrize("value", [
    None, "", "X", "s", "SX", "S!", "!!S", "S+*", "S**", "++", "!S+", "!S*", "+", "*", "!", "S 0",
    "S0", "0S", "0+", "0*", "!0", "SA +", "ZZ", "SYN", "٣",
])
def test_flags_bad_value(value):
    assert _reason(parse_flags_value, value) == "invalid:bad_option_value:flags"


def test_flags_invalid_wins_over_mask():
    assert _reason(parse_flags_value, "X,12") == "invalid:bad_option_value:flags"
    assert _reason(parse_flags_value, "!,12") == "invalid:bad_option_value:flags"


# --- dsize -------------------------------------------------------------------------------------

@pytest.mark.parametrize("value, expected", [
    ("100", DsizeSpec("eq", 100)),
    ("0", DsizeSpec("eq", 0)),
    ("<100", DsizeSpec("lt", 100)),
    (">100", DsizeSpec("gt", 100)),
    ("> 100", DsizeSpec("gt", 100)),
    ("< 5", DsizeSpec("lt", 5)),
    ("100<>200", DsizeSpec("range", 100, 200)),
    ("100 <> 200", DsizeSpec("range", 100, 200)),
    ("5<>5", DsizeSpec("range", 5, 5)),
    ("0<>65535", DsizeSpec("range", 0, 65535)),
    (" 7 ", DsizeSpec("eq", 7)),
    ("4294967295", DsizeSpec("eq", 4294967295)),
    ("<0", DsizeSpec("lt", 0)),          # valid syntax even though it can never match
])
def test_dsize_valid(value, expected):
    assert parse_dsize_value(value) == expected


@pytest.mark.parametrize("value", [
    None, "", " ", "-5", "<-5", ">-1", "5<>-1", "-1<>5", "200<>100", "<>", "5<>", "<>5", "1<>2<>3",
    "abc", "<abc", "1.5", "+5", "<=5", ">=5", "=5", "<", ">", "1 0", "1<5", "٣", "4294967296",
    "9" * 5000, "<" + "9" * 5000, "1<>" + "9" * 5000,
])
def test_dsize_bad(value):
    assert _reason(parse_dsize_value, value) == "invalid:bad_option_value:dsize"


# --- option-level wrappers ---------------------------------------------------------------------

def test_absent_options_give_none():
    o = _opts('msg:"x"; sid:1;')
    assert parse_flow(o) is None and parse_flags(o) is None and parse_dsize(o) is None


def test_wrappers_find_the_option():
    o = _opts('msg:"x"; flow:to_server,established; flags:S+; dsize:>10; sid:1;')
    assert parse_flow(o) == FlowSpec("to_server", "established")
    assert parse_flags(o) == FlagsSpec("all", frozenset("S"))
    assert parse_dsize(o) == DsizeSpec("gt", 10)


@pytest.mark.parametrize("fn, name, body", [
    (parse_flow, "flow", "flow:to_server; flow:to_client;"),
    (parse_flags, "flags", "flags:S; flags:A;"),
    (parse_dsize, "dsize", "dsize:1; dsize:2;"),
])
def test_duplicate_option(fn, name, body):
    assert _reason(fn, _opts(body)) == f"invalid:duplicate_option:{name}"


def test_bare_keywords_are_bad_values():
    assert _reason(parse_flow, _opts("flow;")) == "invalid:bad_option_value:flow"
    assert _reason(parse_flags, _opts("flags;")) == "invalid:bad_option_value:flags"
    assert _reason(parse_dsize, _opts("dsize;")) == "invalid:bad_option_value:dsize"


def test_flags_spec_model_rules():
    with pytest.raises(ValueError):
        FlagsSpec("all", frozenset())
    with pytest.raises(ValueError):
        FlagsSpec("none", frozenset())
    assert FlagsSpec("exact", frozenset()).flags == frozenset()


def test_blanks_around_values_are_removed_by_the_tokenizer():
    o = _opts('flags: SA ; flow : to_server , established ; dsize :  > 5 ; sid:1;')
    assert parse_flags(o) == FlagsSpec("exact", frozenset("SA"))
    assert parse_flow(o) == FlowSpec("to_server", "established")
    assert parse_dsize(o) == DsizeSpec("gt", 5)
