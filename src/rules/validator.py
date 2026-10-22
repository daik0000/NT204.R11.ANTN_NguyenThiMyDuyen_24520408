import logging
from typing import Any, Dict, List, Optional, Sequence

from src.models.rule import ContentSpec, Rule
from src.models.rule_report import ParseResult
from src.rules.parser import (
    MAX_OPTION_INT, OptionPair, RuleSyntaxError, parse_contents_full, parse_dsize, parse_flags, parse_flow,
    parse_header, parse_identification, tokenize_rule, unsupported_keyword,
)

logger = logging.getLogger(__name__)

DEFAULT_PRIORITY = 3        # used only when cfg has no engine.default_priority


def validate_contents(contents: Sequence[ContentSpec]) -> None:
    """
    Cross-option checks on the content list, per content in rule order.

    Raises RuleSyntaxError:
      invalid:depth_lt_pattern         depth is smaller than the pattern length
      invalid:within_lt_pattern        within is smaller than the pattern length
      invalid:mixed_absolute_relative  the same content has offset/depth and also distance/within
    A depth or within equal to the pattern length is fine.
    """
    for c in contents:
        if c.depth is not None and c.depth < len(c.pattern):
            raise RuleSyntaxError("invalid:depth_lt_pattern")
        if c.within is not None and c.within < len(c.pattern):
            raise RuleSyntaxError("invalid:within_lt_pattern")
        if (c.offset is not None or c.depth is not None) and \
                (c.distance is not None or c.within is not None):
            raise RuleSyntaxError("invalid:mixed_absolute_relative")


def validate_flags_protocol(protocol_token: str, has_flags: bool) -> None:
    """flags is a TCP option: with a udp rule it is invalid:flags_requires_tcp (tcp and ip are ok)."""
    if has_flags and protocol_token == "udp":
        raise RuleSyntaxError("invalid:flags_requires_tcp")


def _best_effort_sid(options: List[OptionPair]) -> Optional[int]:
    """The sid if there is exactly one well-formed 'sid' option, else None (for reports only)."""
    values = [v for k, v in options if k == "sid"]
    if len(values) == 1 and values[0] is not None and values[0].isascii() and values[0].isdigit():
        try:
            n = int(values[0])
        except ValueError:
            return None
        return n if 1 <= n <= MAX_OPTION_INT else None
    return None


def _default_priority(cfg: Optional[Dict[str, Any]]) -> int:
    try:
        return cfg["engine"]["default_priority"]
    except (TypeError, KeyError):
        return DEFAULT_PRIORITY


def parse_rule(text: str, source_file: str = "", line_no: int = 0,
               cfg: Optional[Dict[str, Any]] = None) -> ParseResult:
    """
    Parse one logical rule line into a ParseResult. Never raises.

    Stateless: no global state and no sid bookkeeping, so it can be tested alone and reloaded
    freely. Duplicate sids and disabled sids are the Loader's job; this function never returns
    invalid:duplicate_sid or disabled:sid.

    Use with the Loader as parse_fn=functools.partial(parse_rule, cfg=cfg). cfg is the full config;
    only cfg["engine"]["default_priority"] is read (3 if absent).

    Classification order: structure (tokenizer) -> header -> supported options (values and
    cross-option checks) -> keywords outside the subset. ANY invalid at any step wins over every
    unsupported. When there are several unsupported reasons the order is: header, then value-level
    ones in this order (content negation, flow option, flags mask), then an unknown keyword.
    Because of that a header or option that is merely unsupported does not stop the remaining
    options from being checked.

    The ParseResult carries the sid whenever exactly one well-formed sid option was found, even
    for a rejected rule. A bug in the parser itself becomes invalid:internal_error.
    """
    try:
        return _parse_rule(text, source_file, line_no, cfg)
    except Exception as e:                      # defensive: one bad line must not stop the load
        logger.warning("internal error parsing %s:%d: %r", source_file, line_no, e, exc_info=True)
        return ParseResult("invalid", reason="invalid:internal_error")


def _parse_rule(text: str, source_file: str, line_no: int,
                cfg: Optional[Dict[str, Any]]) -> ParseResult:
    # 1. structure
    try:
        header_tokens, options = tokenize_rule(text)
    except RuleSyntaxError as e:
        return ParseResult("invalid", reason=e.reason)

    sid = _best_effort_sid(options)

    def rejected(reason: str) -> ParseResult:
        status = "invalid" if reason.startswith("invalid:") else "unsupported"
        return ParseResult(status, reason=reason, sid=sid)

    unsupported: List[str] = []

    # 2. header (a broken header is not trusted: stop; a merely unsupported one is remembered)
    header = None
    try:
        header = parse_header(header_tokens)
    except RuleSyntaxError as e:
        if e.reason.startswith("invalid:"):
            return rejected(e.reason)
        header_unsupported = e.reason
    else:
        header_unsupported = None
    if header_unsupported:
        unsupported.append(header_unsupported)

    # 3. supported options: values, then cross-option checks
    try:
        ident = parse_identification(options, _default_priority(cfg))
    except RuleSyntaxError as e:
        return rejected(e.reason)

    contents: tuple = ()
    flow = flags = dsize = None
    for name, parser in (("contents", parse_contents_full), ("flow", parse_flow),
                         ("flags", parse_flags), ("dsize", parse_dsize)):
        try:
            value = parser(options)
        except RuleSyntaxError as e:
            if e.reason.startswith("invalid:"):
                return rejected(e.reason)
            unsupported.append(e.reason)
            continue
        if name == "contents":
            contents, content_unsupported = value
            if content_unsupported:
                unsupported.append(content_unsupported)
        elif name == "flow":
            flow = value
        elif name == "flags":
            flags = value
        else:
            dsize = value

    # cross-option checks need the parsed values; flags is checked even if its mask was unsupported
    flags_present = any(k == "flags" for k, _ in options)
    try:
        validate_contents(contents)
        validate_flags_protocol(header_tokens[1], flags_present)
    except RuleSyntaxError as e:
        return rejected(e.reason)

    # 4. keywords outside the subset
    keyword_reason = unsupported_keyword(options)
    if keyword_reason:
        unsupported.append(keyword_reason)

    if unsupported:
        return rejected(unsupported[0])

    rule = Rule(
        action=header.action, protocol=header.protocol,
        src_ip=header.src_ip, src_port=header.src_port, direction=header.direction,
        dst_ip=header.dst_ip, dst_port=header.dst_port,
        msg=ident.msg, sid=ident.sid, rev=ident.rev, classtype=ident.classtype,
        priority=ident.priority, contents=contents, flow=flow, flags=flags, dsize=dsize,
        passive_options=ident.passive_options,
        source_file=source_file, line_no=line_no, raw=text,
    )
    return ParseResult("valid", rule=rule, sid=rule.sid)
