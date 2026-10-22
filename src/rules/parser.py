import ipaddress
import re
from dataclasses import dataclass
from typing import List, NamedTuple, Optional, Tuple

from src.models.rule import (
    ContentSpec, PORT_MAX, PORT_MIN, RULE_ACTIONS, RULE_DIRECTIONS, RULE_PROTOCOLS, IpSpec, PortSpec,
    RuleAction, RuleDirection, RuleProtocol,
)
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


# Real Snort words that this engine does not implement -> unsupported, not invalid.
UNSUPPORTED_ACTIONS = ("drop", "reject", "pass", "log", "sdrop", "activate", "dynamic")
UNSUPPORTED_PROTOCOLS = (
    "icmp", "icmpv6", "http", "dns", "smtp", "ftp", "ssh", "tls", "ssl", "smb",
    "pop3", "imap", "telnet", "snmp", "sip", "tftp", "ntp", "dhcp", "rdp",
)


def parse_action(token: str) -> RuleAction:
    """
    'alert' only (lower case).
    unsupported:action:<x>  drop | reject | pass | log | sdrop | activate | dynamic
    invalid:bad_header      any other word
    """
    if token in RULE_ACTIONS:
        return token
    if token in UNSUPPORTED_ACTIONS:
        raise RuleSyntaxError(f"unsupported:action:{token}")
    raise RuleSyntaxError("invalid:bad_header")


def parse_protocol(token: str) -> RuleProtocol:
    """
    'tcp' | 'udp' | 'ip' (lower case).
    unsupported:protocol:<x>  icmp, http, dns, ... (application protocols are Snort 3 syntax and
                              out of scope; see UNSUPPORTED_PROTOCOLS)
    invalid:bad_header        any other word
    """
    if token in RULE_PROTOCOLS:
        return token
    if token in UNSUPPORTED_PROTOCOLS:
        raise RuleSyntaxError(f"unsupported:protocol:{token}")
    raise RuleSyntaxError("invalid:bad_header")


def parse_direction(token: str) -> RuleDirection:
    """
    '->' | '<>'.
    invalid:bad_direction  anything else, including '<-' (Snort 2 has no such operator)
    """
    if token in RULE_DIRECTIONS:
        return token
    raise RuleSyntaxError("invalid:bad_direction")


class Header(NamedTuple):
    action: RuleAction
    protocol: RuleProtocol
    src_ip: IpSpec
    src_port: PortSpec
    direction: RuleDirection
    dst_ip: IpSpec
    dst_port: PortSpec


def parse_header(tokens: List[str]) -> Header:
    """
    Parse the 7 header tokens (action proto src_ip src_port direction dst_ip dst_port).

    Every field is checked. ANY 'invalid:*' error wins over an 'unsupported:*' one. Within the
    same kind, the first field in header order is reported. Raises RuleSyntaxError.

    What the caller (parse_rule) must do with the two kinds of error:
    - 'invalid:*' header: the line is not trusted; return invalid at once, do not look at options.
    - 'unsupported:*' header: do NOT let the exception leave parse_rule. Remember it, still parse
      the options to look for an 'invalid:*' error (invalid wins over unsupported), and only if the
      options are clean report the header's unsupported reason, before any unsupported:keyword
      found in the options.
    """
    if len(tokens) != HEADER_TOKEN_COUNT:
        raise RuleSyntaxError("invalid:bad_header")
    parsers = (parse_action, parse_protocol, parse_ip, parse_port,
               parse_direction, parse_ip, parse_port)

    values = []
    first_unsupported: Optional[RuleSyntaxError] = None
    for fn, token in zip(parsers, tokens):
        try:
            values.append(fn(token))
        except RuleSyntaxError as e:
            if e.reason.startswith("invalid:"):
                raise
            if first_unsupported is None:
                first_unsupported = e
    if first_unsupported is not None:
        raise first_unsupported
    return Header(*values)


# --- Options -------------------------------------------------------------------------------
#
# Every option keyword falls in exactly one of these sets. A keyword in none of them is
# UNSUPPORTED (unsupported:keyword:<k>), never silently ignored: ignoring it would make a rule
# match more than its author meant (e.g. dropping pcre or flowbits widens the rule).

# Identification options, parsed into Identification below.
IDENTIFICATION_KEYWORDS = ("msg", "sid", "rev", "classtype", "priority")

# Accepted but only stored (Rule.passive_options): they never change whether a packet matches.
PASSIVE_KEYWORDS = ("reference", "metadata", "gid")

# Options that take part in matching; each has its own parser (content and its modifiers, flow,
# flags, dsize).
MATCH_KEYWORDS = ("content", "nocase", "offset", "depth", "distance", "within",
                  "flow", "flags", "dsize")

SUPPORTED_KEYWORDS = IDENTIFICATION_KEYWORDS + PASSIVE_KEYWORDS + MATCH_KEYWORDS

_CLASSTYPE_RE = re.compile(r"[A-Za-z0-9_-]+")


@dataclass(frozen=True)
class Identification:
    """msg/sid/rev/classtype/priority of a rule plus its stored-only options."""
    msg: str
    sid: int
    rev: int
    classtype: Optional[str]
    priority: int
    passive_options: Tuple[OptionPair, ...]


def unsupported_keyword(options: List[OptionPair]) -> Optional[str]:
    """
    Reason code for the first option whose keyword is not in SUPPORTED_KEYWORDS, else None.
    Keywords are case-sensitive, as in Snort ('SID' is not 'sid').
    """
    for key, _ in options:
        if key not in SUPPORTED_KEYWORDS:
            return f"unsupported:keyword:{key}"
    return None


def unquote_string(value: Optional[str]) -> Optional[str]:
    """
    Value of a "..." option as text, or None if it is not a well-formed quoted string.

    The value must start and end with '"', with no other unescaped '"' inside. Escapes \\; \\" and
    \\\\ become ';', '"' and a backslash; any other backslash pair is kept as written.
    """
    if value is None or len(value) < 2 or value[0] != '"' or value[-1] != '"':
        return None
    inner = value[1:-1]
    out: List[str] = []
    i, n = 0, len(inner)
    while i < n:
        ch = inner[i]
        if ch == "\\":
            if i + 1 >= n:
                return None                  # the closing quote was itself escaped
            nxt = inner[i + 1]
            out.append(nxt if nxt in ';"\\' else ch + nxt)
            i += 2
            continue
        if ch == '"':
            return None                      # unescaped quote in the middle
        out.append(ch)
        i += 1
    return "".join(out)


MAX_OPTION_INT = 0xFFFFFFFF      # sid/rev/priority are 32-bit in Snort


def _positive_int(text: Optional[str]) -> Optional[int]:
    """int in 1..MAX_OPTION_INT from ASCII digits, else None (never raises)."""
    if text is None or not _is_ascii_digits(text):
        return None
    try:
        n = int(text)                    # a 5000-digit string raises ValueError on recent Python
    except ValueError:
        return None
    return n if 1 <= n <= MAX_OPTION_INT else None


def parse_identification(options: List[OptionPair], default_priority: int = 3) -> Identification:
    """
    Parse msg, sid, rev, classtype, priority and collect the stored-only options.

    Options owned by other parsers (MATCH_KEYWORDS) and unknown keywords are ignored here; use
    unsupported_keyword() for the latter.

    Raises RuleSyntaxError, reporting the first problem found in rule order:
      invalid:duplicate_option:<k>  msg, sid, rev, classtype or priority given twice
      invalid:bad_sid               sid is not an integer in 1..4294967295 (or has no value)
      invalid:bad_option_value:<k>  rev/priority not an integer in 1..4294967295, classtype not a plain name
      invalid:missing_msg           msg absent, not in double quotes, or badly quoted
    and, only when the options above are fine:
      invalid:missing_sid           no sid
      invalid:missing_msg           no msg
    msg is unquoted ('\\;' '\\"' '\\\\' decoded). rev defaults to 1, priority to default_priority.
    reference, metadata and gid may repeat and are kept verbatim; their values are not checked.
    """
    seen = set()
    msg: Optional[str] = None
    sid: Optional[int] = None
    rev = 1
    classtype: Optional[str] = None
    priority = default_priority
    passive: List[OptionPair] = []

    for key, value in options:
        if key in PASSIVE_KEYWORDS:
            passive.append((key, value))
            continue
        if key not in IDENTIFICATION_KEYWORDS:
            continue
        if key in seen:
            raise RuleSyntaxError(f"invalid:duplicate_option:{key}")
        seen.add(key)

        if key == "msg":
            msg = unquote_string(value)
            if msg is None:
                raise RuleSyntaxError("invalid:missing_msg")
        elif key == "sid":
            sid = _positive_int(value)
            if sid is None:
                raise RuleSyntaxError("invalid:bad_sid")
        elif key == "rev":
            rev = _positive_int(value)
            if rev is None:
                raise RuleSyntaxError("invalid:bad_option_value:rev")
        elif key == "priority":
            priority = _positive_int(value)
            if priority is None:
                raise RuleSyntaxError("invalid:bad_option_value:priority")
        else:                                # classtype
            if value is None or not _CLASSTYPE_RE.fullmatch(value):
                raise RuleSyntaxError("invalid:bad_option_value:classtype")
            classtype = value

    if sid is None:
        raise RuleSyntaxError("invalid:missing_sid")
    if msg is None:
        raise RuleSyntaxError("invalid:missing_msg")
    return Identification(msg, sid, rev, classtype, priority, tuple(passive))


# --- content and its modifiers -------------------------------------------------------------

_HEX_DIGITS = frozenset("0123456789abcdefABCDEF")
_CONTENT_MODIFIERS = ("nocase", "offset", "depth", "distance", "within")


def decode_content(value: Optional[str]) -> Tuple[str, bytes]:
    """
    Decode the value of a content option into (raw, pattern).

    value is the text after 'content:' and must be a double-quoted string. raw is the text between
    the quotes exactly as written; pattern is the bytes to look for:
    - \\; \\" and \\\\ stand for ';', '"' and a backslash; any other backslash pair is kept
      as two characters.
    - |41 42 7c| is a hex block (case-insensitive, blanks allowed anywhere inside, an even number
      of digits). Text and hex blocks may be mixed: "GE|54|" is b"GET".
    - Every other character is encoded as UTF-8, the same bytes it has in the rule file (which
      the Loader reads as UTF-8): 'é' is b"\\xc3\\xa9". The replacement character U+FFFD, which the
      Loader puts in place of a byte that was not valid UTF-8, is rejected so such a rule cannot
      match by accident. Any raw byte can be written with a hex block.

    Raises RuleSyntaxError('unsupported:content_negation') for content:!"...", and
    RuleSyntaxError('invalid:bad_option_value:content') for a missing value, a value that is not
    in double quotes, an unterminated or odd/non-hex block, U+FFFD or another unencodable
    character, or an empty pattern.
    """
    if value is not None and value.startswith('!"'):
        raise RuleSyntaxError("unsupported:content_negation")
    if value is None or len(value) < 2 or value[0] != '"' or value[-1] != '"':
        raise _bad_content()

    raw = value[1:-1]
    out = bytearray()
    in_hex = False
    hex_digits: List[str] = []
    i, n = 0, len(raw)
    while i < n:
        ch = raw[i]
        if in_hex:
            if ch == "|":
                if len(hex_digits) % 2:
                    raise _bad_content()
                out += bytes.fromhex("".join(hex_digits))
                hex_digits = []
                in_hex = False
            elif ch in _HEX_DIGITS:
                hex_digits.append(ch)
            elif ch not in " \t":
                raise _bad_content()
            i += 1
            continue
        if ch == "|":
            in_hex = True
            i += 1
        elif ch == "\\":
            if i + 1 >= n:
                raise _bad_content()
            nxt = raw[i + 1]
            out += _encode_text(nxt if nxt in ';"\\' else ch + nxt)
            i += 2
        elif ch == '"':
            raise _bad_content()            # unescaped quote inside the string
        else:
            out += _encode_text(ch)
            i += 1

    if in_hex or not out:
        raise _bad_content()
    return raw, bytes(out)


def _bad_content() -> RuleSyntaxError:
    return RuleSyntaxError("invalid:bad_option_value:content")


def _encode_text(text: str) -> bytes:
    """UTF-8 bytes of rule text; U+FFFD (a decoding replacement) or a lone surrogate is rejected."""
    if "\ufffd" in text:
        raise _bad_content()
    try:
        return text.encode("utf-8")
    except UnicodeEncodeError:
        raise _bad_content() from None


def _modifier_value(key: str, value: Optional[str]):
    """Parsed value of a content modifier, or raise invalid:bad_option_value:<key>."""
    def bad() -> RuleSyntaxError:
        return RuleSyntaxError(f"invalid:bad_option_value:{key}")

    if key == "nocase":
        if value is not None:
            raise bad()
        return True
    if value is None:
        raise bad()
    if key == "distance":
        negative = value.startswith("-")
        number = _non_negative_int(value[1:] if negative else value)
        if number is None:
            raise bad()
        return -number if negative else number
    number = _non_negative_int(value)
    if number is None or (key == "within" and number < 1):
        raise bad()
    return number


def _non_negative_int(text: str) -> Optional[int]:
    """int in 0..MAX_OPTION_INT from ASCII digits, else None (never raises)."""
    if not _is_ascii_digits(text):
        return None
    try:
        n = int(text)
    except ValueError:
        return None
    return n if n <= MAX_OPTION_INT else None


def parse_contents(options: List[OptionPair]) -> Tuple[ContentSpec, ...]:
    """
    Build the ContentSpec list from the options, keeping the rule order (distance/within are
    relative to the previous content, so the order matters).

    Each modifier (nocase, offset, depth, distance, within) applies to the content right before
    it. offset/depth are integers >= 0, within >= 1, distance any integer (negative allowed),
    nocase takes no value.

    Raises RuleSyntaxError, first problem in rule order:
      invalid:modifier_without_content  a modifier before any content
      invalid:duplicate_option:<k>      the same modifier twice on one content
      invalid:bad_option_value:<k>      bad modifier value, or bad content (<k> is 'content')
    unsupported:content_negation is raised only at the end, so an invalid option anywhere wins
    over it (the negated content itself is dropped and its modifiers are still checked).
    """
    contents: List[ContentSpec] = []
    current: Optional[dict] = None            # the content being built (None = none yet)
    negated_seen = False

    def close() -> None:
        if current is not None and not current["negated"]:
            contents.append(ContentSpec(current["raw"], current["pattern"], **current["mods"]))

    for key, value in options:
        if key == "content":
            close()
            negated = False
            raw, pattern = "", b""
            try:
                raw, pattern = decode_content(value)
            except RuleSyntaxError as e:
                if e.reason != "unsupported:content_negation":
                    raise
                negated = negated_seen = True
            current = {"raw": raw, "pattern": pattern, "negated": negated, "mods": {}, "seen": set()}
        elif key in _CONTENT_MODIFIERS:
            if current is None:
                raise RuleSyntaxError("invalid:modifier_without_content")
            if key in current["seen"]:
                raise RuleSyntaxError(f"invalid:duplicate_option:{key}")
            current["seen"].add(key)
            current["mods"][key] = _modifier_value(key, value)
    close()

    if negated_seen:
        raise RuleSyntaxError("unsupported:content_negation")
    return tuple(contents)
