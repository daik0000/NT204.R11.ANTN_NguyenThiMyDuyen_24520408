import pytest

from src.models.rule_report import is_valid_reason
from src.rules.parser import RuleSyntaxError, tokenize_rule

HEAD = "alert tcp any any -> any 80"


def _reason(text):
    with pytest.raises(RuleSyntaxError) as exc:
        tokenize_rule(text)
    assert is_valid_reason(exc.value.reason)
    return exc.value.reason


def test_basic_rule():
    header, opts = tokenize_rule(f'{HEAD} (msg:"x"; content:"../"; nocase; sid:1;)')
    assert header == ["alert", "tcp", "any", "any", "->", "any", "80"]
    assert opts == [("msg", '"x"'), ("content", '"../"'), ("nocase", None), ("sid", "1")]


def test_tabs_extra_spaces_and_surrounding_blanks():
    header, opts = tokenize_rule(f'  alert\ttcp  any any   ->\tany 80 (  sid : 1 ;  rev:2 ;) \t')
    assert header[0] == "alert" and header[-1] == "80"
    assert opts == [("sid", "1"), ("rev", "2")]


def test_semicolon_inside_quotes_does_not_split():
    _, opts = tokenize_rule(f'{HEAD} (msg:"a;b"; sid:1;)')
    assert opts == [("msg", '"a;b"'), ("sid", "1")]


def test_escaped_semicolon_does_not_split():
    _, opts = tokenize_rule(f'{HEAD} (content:"x\\;y"; sid:1;)')
    assert opts == [("content", '"x\\;y"'), ("sid", "1")]
    _, opts = tokenize_rule(f'{HEAD} (msg:a\\;b; sid:1;)')       # also outside quotes
    assert opts == [("msg", "a\\;b"), ("sid", "1")]


def test_escaped_quote_does_not_close_string():
    _, opts = tokenize_rule(f'{HEAD} (msg:"say \\"hi\\"; ok"; sid:1;)')
    assert opts == [("msg", '"say \\"hi\\"; ok"'), ("sid", "1")]


def test_escaped_backslash_before_closing_quote():
    _, opts = tokenize_rule(f'{HEAD} (content:"a\\\\"; sid:1;)')
    assert opts == [("content", '"a\\\\"'), ("sid", "1")]


def test_value_split_at_first_colon_only():
    _, opts = tokenize_rule(f'{HEAD} (msg:"a:b:c"; flow:to_server,established; sid:1;)')
    assert opts[0] == ("msg", '"a:b:c"')
    assert opts[1] == ("flow", "to_server,established")


def test_parens_inside_quotes():
    _, opts = tokenize_rule(f'{HEAD} (msg:"f(x)"; content:"a)b"; sid:1;)')
    assert opts == [("msg", '"f(x)"'), ("content", '"a)b"'), ("sid", "1")]


def test_quoted_value_inner_whitespace_kept():
    _, opts = tokenize_rule(f'{HEAD} (content:"  x  "; sid:1;)')
    assert opts[0] == ("content", '"  x  "')


def test_empty_options_ignored():
    _, opts = tokenize_rule(f"{HEAD} (;; sid:1;; ;)")
    assert opts == [("sid", "1")]


def test_no_trailing_semicolon_ok():
    _, opts = tokenize_rule(f"{HEAD} (sid:1)")
    assert opts == [("sid", "1")]


def test_empty_option_list():
    assert tokenize_rule(f"{HEAD} ()")[1] == []
    assert tokenize_rule(f"{HEAD} (  ;  )")[1] == []


def test_empty_value_kept_as_empty_string():
    assert tokenize_rule(f"{HEAD} (sid:;)")[1] == [("sid", "")]


def test_duplicate_options_preserved_in_order():
    _, opts = tokenize_rule(f'{HEAD} (content:"a"; content:"b"; sid:1; sid:2;)')
    assert [k for k, _ in opts] == ["content", "content", "sid", "sid"]


@pytest.mark.parametrize("text", [
    "alert tcp any any -> any 80",                      # no parentheses
    f"{HEAD} (sid:1;",                                  # missing ')'
    f"{HEAD} )sid:1;(",                                 # ')' before '('
    f"{HEAD} (sid:1;) extra",                           # text after ')'
    f"{HEAD} (sid:1;);",                                # ';' after ')'
    f'{HEAD} (msg:"x; sid:1;)',                         # unterminated quote
    f"{HEAD} (:value; sid:1;)",                         # empty key
    "",
    "   ",
])
def test_malformed_rule(text):
    assert _reason(text) == "invalid:malformed_rule"


@pytest.mark.parametrize("head", [
    "alert tcp any any -> any",                         # 6 tokens
    "alert tcp any any -> any 80 extra",                # 8 tokens
    "(",
])
def test_bad_header_token_count(head):
    text = f"{head} (sid:1;)" if head != "(" else "(sid:1;)"
    assert _reason(text) == "invalid:bad_header"


def test_structure_checked_before_header():
    assert _reason("alert tcp (sid:1;") == "invalid:malformed_rule"


def test_header_with_no_tokens_and_options():
    assert _reason("() ") == "invalid:bad_header"


def test_token_values_unchanged():
    header, _ = tokenize_rule("alert tcp !10.0.0.0/8 [80,443] <> $HOME_NET any (sid:1;)")
    assert header == ["alert", "tcp", "!10.0.0.0/8", "[80,443]", "<>", "$HOME_NET", "any"]


def test_backslash_at_end_of_body_does_not_crash():
    header, opts = tokenize_rule(HEAD + " (sid:1;" + chr(92) + ")")
    assert opts[0] == ("sid", "1") and len(header) == 7


def test_syntax_error_rejects_unknown_reason():
    with pytest.raises(ValueError):
        RuleSyntaxError("invalid:made_up")
