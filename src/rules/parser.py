from typing import List, Optional, Tuple

from src.models.rule_report import is_valid_reason

HEADER_TOKEN_COUNT = 7      # action proto src_ip src_port direction dst_ip dst_port

OptionPair = Tuple[str, Optional[str]]


class RuleSyntaxError(Exception):
    """A rule line that cannot be taken apart; `reason` is a code from rule_report.REASON_CODES."""

    def __init__(self, reason: str):
        if not is_valid_reason(reason):
            raise ValueError(f"unknown reason code: {reason!r}")
        super().__init__(reason)
        self.reason = reason


def tokenize_rule(text: str) -> Tuple[List[str], List[OptionPair]]:
    """
    Split one rule line into (header_tokens, options). Nothing is interpreted here.

    header_tokens: the 7 whitespace-separated words before the first '(':
        action proto src_ip src_port direction dst_ip dst_port.
    options: (key, value) pairs in rule order, taken from between the first '(' and the last ')'.
        A bare keyword ('nocase') is (key, None); 'key:value' is split at the FIRST ':' so a
        value may contain ':'. Key and value are stripped of surrounding blanks; the inside of a
        quoted value is kept exactly as written, escapes included (the option parsers decode it).

    Options are split on ';' by a character scanner, because a ';' inside "..." or escaped as
    '\\;' belongs to the value. Empty options (';;' or a trailing ';') are ignored.

    Raises RuleSyntaxError:
      invalid:malformed_rule  no '(' or no ')' after it, anything but blanks after the last
                              ')', an unterminated quote, or an option with an empty key
      invalid:bad_header      the header does not have exactly 7 tokens
    The structure is checked before the header, so a line with both problems reports
    malformed_rule.
    """
    text = text.strip()

    open_idx = text.find("(")
    if open_idx == -1:
        raise RuleSyntaxError("invalid:malformed_rule")
    close_idx = text.rfind(")")
    if close_idx < open_idx:
        raise RuleSyntaxError("invalid:malformed_rule")
    if text[close_idx + 1:].strip():
        raise RuleSyntaxError("invalid:malformed_rule")

    options = _split_options(text[open_idx + 1:close_idx])

    header_tokens = text[:open_idx].split()
    if len(header_tokens) != HEADER_TOKEN_COUNT:
        raise RuleSyntaxError("invalid:bad_header")
    return header_tokens, options


def _split_options(body: str) -> List[OptionPair]:
    """Scan `body` once, cutting at ';' that is outside quotes and not escaped."""
    pieces: List[str] = []
    current: List[str] = []
    in_quote = False
    i, n = 0, len(body)
    while i < n:
        ch = body[i]
        if ch == "\\" and i + 1 < n:
            current.append(ch)
            current.append(body[i + 1])      # escaped char is never a delimiter or a quote
            i += 2
            continue
        if ch == '"':
            in_quote = not in_quote
        if ch == ";" and not in_quote:
            pieces.append("".join(current))
            current = []
        else:
            current.append(ch)
        i += 1

    if in_quote:
        raise RuleSyntaxError("invalid:malformed_rule")
    pieces.append("".join(current))

    options: List[OptionPair] = []
    for piece in pieces:
        piece = piece.strip()
        if not piece:
            continue
        key, sep, value = piece.partition(":")
        key = key.strip()
        if not key:
            raise RuleSyntaxError("invalid:malformed_rule")
        options.append((key, value.strip() if sep else None))
    return options
