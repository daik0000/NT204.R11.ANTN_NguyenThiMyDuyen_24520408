"""
Result of parsing one rule line, one line of rules_report.jsonl, and the load summary.

Status values. ParseResult uses RULE_STATUSES: 'valid' | 'invalid' | 'unsupported'.
RuleRecord uses RECORD_STATUSES = RULE_STATUSES + 'disabled'.
  valid       the line became a Rule.
  invalid     the rule is wrong (syntax or semantics); reason starts with 'invalid:'.
  unsupported the rule is well-formed Snort but outside the supported subset;
              reason starts with 'unsupported:'.
  disabled    (RuleRecord only) a valid rule switched off by engine.disabled_sids;
              reason is 'disabled:sid' and sid is set. The parser never produces it,
              the loader does.

Reason codes are fixed: tests and rules_report.jsonl rely on them. A reason is
None only for status 'valid'. <k>/<x> stand for the offending keyword/option/value.

Fixed codes (REASON_CODES, including the unsupported:* and disabled:* ones listed below):
  invalid:malformed_rule             cannot split into header + options
  invalid:bad_header                 header does not have the expected fields
  invalid:bad_ip                     malformed IPv4 / CIDR
  invalid:bad_port                   malformed port or range outside 0..65535
  invalid:bad_direction              direction is not '->' or '<>'
  invalid:missing_sid                no sid option
  invalid:bad_sid                    sid is not a positive integer
  invalid:duplicate_sid              sid already used by an earlier rule
  invalid:missing_msg                no msg option
  invalid:modifier_without_content   content modifier with no preceding content
  invalid:depth_lt_pattern           depth smaller than the pattern length
  invalid:within_lt_pattern          within smaller than the pattern length
  invalid:mixed_absolute_relative    offset/depth mixed with distance/within on one content
  invalid:flags_requires_tcp         flags used on a non-TCP rule
  invalid:conflicting_flow           contradictory flow options
  invalid:internal_error             unexpected parser failure (the rule is skipped)
Parameterised codes (REASON_PREFIXES, followed by the value):
  invalid:bad_option_value:<k>       option <k> has an unusable value
  invalid:duplicate_option:<k>       option <k> given more than once
  unsupported:action:<x>             action other than the supported ones
  unsupported:protocol:<x>           protocol other than the supported ones
  unsupported:keyword:<k>            option keyword outside the subset (e.g. pcre)
  unsupported:flow_option:<x>        flow value outside the subset
More fixed codes:
  unsupported:ip_syntax              IP list / negation / variable
  unsupported:port_syntax            port list / negation / variable
  unsupported:flags_mask             flags with a mask (e.g. 'S,12')
  unsupported:content_negation       content:!"..."
  disabled:sid                       rule sid listed in engine.disabled_sids (RuleRecord only)

LoadReport counters (all non-negative ints):
  total_lines, blank, comment, rule_lines   line classification over all files read;
                                            these count LOGICAL lines, i.e. after a
                                            trailing '\\' has joined physical lines into one
  valid, invalid, unsupported               outcome of each rule line
  disabled                                  valid rules switched off by engine.disabled_sids
  files_failed                              rule files that could not be read
  disabled_files                            rule files skipped because enabled is false
                                            (not read, so they add nothing to the line counters)
Invariants: total_lines == blank + comment + rule_lines, and
rule_lines == valid + invalid + unsupported + disabled. A disabled rule is NOT counted
in 'valid': 'valid' is the number of rules that stay active.
"""
from dataclasses import asdict, dataclass
from typing import Any, Dict, Literal, Optional

from src.models.rule import Rule

RuleStatus = Literal["valid", "invalid", "unsupported"]
RULE_STATUSES = ("valid", "invalid", "unsupported")

RecordStatus = Literal["valid", "invalid", "unsupported", "disabled"]
RECORD_STATUSES = RULE_STATUSES + ("disabled",)

REASON_CODES = (
    "invalid:malformed_rule",
    "invalid:bad_header",
    "invalid:bad_ip",
    "invalid:bad_port",
    "invalid:bad_direction",
    "invalid:missing_sid",
    "invalid:bad_sid",
    "invalid:duplicate_sid",
    "invalid:missing_msg",
    "invalid:modifier_without_content",
    "invalid:depth_lt_pattern",
    "invalid:within_lt_pattern",
    "invalid:mixed_absolute_relative",
    "invalid:flags_requires_tcp",
    "invalid:conflicting_flow",
    "invalid:internal_error",
    "unsupported:ip_syntax",
    "unsupported:port_syntax",
    "unsupported:flags_mask",
    "unsupported:content_negation",
    "disabled:sid",
)

REASON_PREFIXES = (
    "invalid:bad_option_value:",
    "invalid:duplicate_option:",
    "unsupported:action:",
    "unsupported:protocol:",
    "unsupported:keyword:",
    "unsupported:flow_option:",
)


def is_valid_reason(reason: str) -> bool:
    """True if reason is a fixed code or a known prefix followed by a non-empty value."""
    if not isinstance(reason, str):
        return False
    if reason in REASON_CODES:
        return True
    return any(reason.startswith(p) and len(reason) > len(p) for p in REASON_PREFIXES)


def _check_status_reason(status: str, reason: Optional[str], allowed=RULE_STATUSES) -> None:
    if status not in allowed:
        raise ValueError(f"invalid status: {status!r}")
    if status == "valid":
        if reason is not None:
            raise ValueError("reason must be None when status is 'valid'")
        return
    if reason is None or not is_valid_reason(reason):
        raise ValueError(f"unknown reason code: {reason!r}")
    if not reason.startswith(status + ":"):
        raise ValueError(f"reason {reason!r} does not match status {status!r}")


@dataclass(frozen=True)
class ParseResult:
    """
    Outcome of parsing one rule line.

    status: 'valid' | 'invalid' | 'unsupported'.
    rule: the Rule when status is 'valid', otherwise None.
    reason: None when valid, otherwise a code from the module docstring.
    sid: the sid when it could be read, even for a rejected rule; else None.
    """
    status: RuleStatus
    rule: Optional[Rule] = None
    reason: Optional[str] = None
    sid: Optional[int] = None

    def __post_init__(self) -> None:
        _check_status_reason(self.status, self.reason)
        if (self.status == "valid") != (self.rule is not None):
            raise ValueError("rule must be set if and only if status is 'valid'")


@dataclass(frozen=True)
class RuleRecord:
    """
    One line of rules_report.jsonl: what happened to one rule line.

    file: path of the rule file. line: 1-based line number.
    status: one of RECORD_STATUSES ('valid' | 'invalid' | 'unsupported' | 'disabled').
    reason/sid: as in ParseResult; a 'disabled' record has reason 'disabled:sid' and a sid.
    text: the rule line verbatim.
    """
    file: str
    line: int
    status: RecordStatus
    reason: Optional[str]
    sid: Optional[int]
    text: str

    def __post_init__(self) -> None:
        _check_status_reason(self.status, self.reason, RECORD_STATUSES)
        if self.status == "disabled" and self.sid is None:
            raise ValueError("a 'disabled' record needs a sid")

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class LoadReport:
    """Counters for one rule-loading run (see the module docstring for meanings)."""
    total_lines: int = 0
    blank: int = 0
    comment: int = 0
    rule_lines: int = 0
    valid: int = 0
    invalid: int = 0
    unsupported: int = 0
    disabled: int = 0
    files_failed: int = 0
    disabled_files: int = 0

    def to_dict(self) -> Dict[str, int]:
        return asdict(self)
