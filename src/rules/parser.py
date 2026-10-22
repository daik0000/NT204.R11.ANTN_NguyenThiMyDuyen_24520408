import ipaddress
from typing import List, Optional, Tuple

from src.models.rule import PORT_MAX, PORT_MIN, IpSpec, PortSpec
from src.models.rule_report import is_valid_reason

HEADER_TOKEN_COUNT = 7      # action proto src_ip src_port direction dst_ip dst_port

OptionPair = Tuple[str, Optional[str]]


class RuleSyntaxError(Exception):
    """
    A rule line (or one of its parts) that is rejected; `reason` is an 'invalid:*' or
    'unsupported:*' code from rule_report.REASON_CODES. The name is historical: it also
    carries unsupported syntax, not only malformed input.
    """

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


_UNSUPPORTED_PREFIXES = ("$", "!", "[")


def _is_ascii_digits(s: str) -> bool:
    return s.isascii() and s.isdigit()


def parse_ip(token: str) -> IpSpec:
    """
    Parse the src_ip / dst_ip token of a rule header into an IpSpec (IPv4 only).

    Accepted: 'any'; a single address ('10.0.0.5' = /32); CIDR ('192.168.1.0/24'). Host bits
    are cleared, so '10.0.0.5/24' gives network 10.0.0.0. The prefix must be decimal digits
    (a dotted netmask such as '/255.255.255.0' is rejected).

    Raises RuleSyntaxError:
      unsupported:ip_syntax  token starts with '$' (variable), '!' (negation) or '[' (list)
      invalid:bad_ip         anything else that is not an IPv4 address/CIDR (300.1.1.1, 10.0.0,
                             1.2.3.4/33, IPv6, empty, ...)
    """
    if token == "any":
        return IpSpec(any=True)
    if token.startswith(_UNSUPPORTED_PREFIXES):
        raise RuleSyntaxError("unsupported:ip_syntax")

    _, sep, prefix = token.partition("/")
    if sep and not _is_ascii_digits(prefix):
        raise RuleSyntaxError("invalid:bad_ip")
    try:
        net = ipaddress.ip_network(token, strict=False)
    except ValueError:
        raise RuleSyntaxError("invalid:bad_ip") from None
    if net.version != 4:
        raise RuleSyntaxError("invalid:bad_ip")
    return IpSpec(any=False, network=int(net.network_address), mask=int(net.netmask))


def parse_port(token: str) -> PortSpec:
    """
    Parse the src_port / dst_port token of a rule header into a PortSpec.

    Accepted: 'any' = (0, 65535); '80' = (80, 80); '1:1024'; ':1023' = (0, 1023);
    '5000:' = (5000, 65535). Only ASCII digits are accepted (no blanks, signs or Unicode digits).

    Raises RuleSyntaxError:
      unsupported:port_syntax  token starts with '$' (variable), '!' (negation) or '[' (list)
      invalid:bad_port         not a number, outside 0..65535, lo > hi, more than one ':', empty
    """
    if token == "any":
        return PortSpec(PORT_MIN, PORT_MAX)
    if token.startswith(_UNSUPPORTED_PREFIXES):
        raise RuleSyntaxError("unsupported:port_syntax")

    lo_text, sep, hi_text = token.partition(":")
    if not sep:
        hi_text = lo_text                    # single port
    elif ":" in hi_text or (not lo_text and not hi_text):
        raise RuleSyntaxError("invalid:bad_port")

    try:
        lo = _port_number(lo_text, PORT_MIN) if sep else _port_number(lo_text, None)
        hi = _port_number(hi_text, PORT_MAX)
    except ValueError:
        raise RuleSyntaxError("invalid:bad_port") from None
    if not (PORT_MIN <= lo <= hi <= PORT_MAX):
        raise RuleSyntaxError("invalid:bad_port")
    return PortSpec(lo, hi)


def _port_number(text: str, default: Optional[int]) -> int:
    """int(text); an empty text gives `default` (open end of a range); ValueError otherwise."""
    if text == "" and default is not None:
        return default
    if not _is_ascii_digits(text):
        raise ValueError(text)
    return int(text)
