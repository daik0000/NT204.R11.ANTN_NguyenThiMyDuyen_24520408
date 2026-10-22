"""
Internal representation of a Snort-style rule (data only, no matching logic).

The matching logic lives in src/engine/. Every spec is a frozen dataclass so an
indexed rule cannot be mutated by mistake. Each enum-like field below has a
tuple of valid values next to its Literal type; keep the two in sync and
update the docstrings when a domain changes (the specs validate against the
tuples in __post_init__, so a missed update fails loudly instead of silently).
"""
from dataclasses import dataclass
from typing import Literal, Optional, Tuple

RuleAction = Literal["alert"]
RULE_ACTIONS = ("alert",)

RuleProtocol = Literal["tcp", "udp", "ip"]
RULE_PROTOCOLS = ("tcp", "udp", "ip")

RuleDirection = Literal["->", "<>"]
RULE_DIRECTIONS = ("->", "<>")

FlowRole = Literal["to_server", "to_client"]
FLOW_ROLES = ("to_server", "to_client")

FlowStateSpec = Literal["established", "not_established"]
FLOW_STATES = ("established", "not_established")

FlagsMode = Literal["exact", "all", "any", "none"]
FLAGS_MODES = ("exact", "all", "any", "none")

# TCP flag letters accepted in FlagsSpec.flags: S=SYN A=ACK F=FIN R=RST P=PSH U=URG C=CWR E=ECE.
# (IDSEvent stores the full names SYN, ACK, ...; the engine maps them to these letters.)
TCP_FLAG_NAMES = ("S", "A", "F", "R", "P", "U", "C", "E")

DsizeOp = Literal["eq", "lt", "gt", "range"]
DSIZE_OPS = ("eq", "lt", "gt", "range")

PORT_MIN = 0
PORT_MAX = 65535


def _require(cond: bool, msg: str) -> None:
    if not cond:
        raise ValueError(msg)


@dataclass(frozen=True)
class IpSpec:
    """
    IPv4 address or CIDR block stored as integers (match: (ip & mask) == network).

    any: True for the rule keyword 'any'; network/mask are then ignored (use 0, 0).
    network: IPv4 network address as a 32-bit unsigned integer.
    mask: netmask as a 32-bit unsigned integer (/32 -> 0xFFFFFFFF).
    """
    any: bool
    network: int = 0
    mask: int = 0

    def __post_init__(self) -> None:
        _require(0 <= self.network <= 0xFFFFFFFF, f"IpSpec.network out of range: {self.network}")
        _require(0 <= self.mask <= 0xFFFFFFFF, f"IpSpec.mask out of range: {self.mask}")


@dataclass(frozen=True)
class PortSpec:
    """
    Inclusive port range lo..hi, both within 0..65535 and lo <= hi.
    A single port is (p, p); 'any' is (0, 65535).
    """
    lo: int
    hi: int

    def __post_init__(self) -> None:
        _require(PORT_MIN <= self.lo <= self.hi <= PORT_MAX, f"invalid port range: {self.lo}:{self.hi}")

    @property
    def is_any(self) -> bool:
        return self.lo == PORT_MIN and self.hi == PORT_MAX


@dataclass(frozen=True)
class ContentSpec:
    """
    One 'content' option with its modifiers.

    raw: the content text as written in the rule (for reports).
    pattern: decoded bytes to search for (|hex| sections and escapes already resolved).
    nocase: case-insensitive match.
    offset/depth: absolute window from the start of the payload (None = not set).
    distance/within: window relative to the end of the previous content match (None = not set).
    """
    raw: str
    pattern: bytes
    nocase: bool = False
    offset: Optional[int] = None
    depth: Optional[int] = None
    distance: Optional[int] = None
    within: Optional[int] = None

    def __post_init__(self) -> None:
        _require(len(self.pattern) > 0, "ContentSpec.pattern must not be empty")


@dataclass(frozen=True)
class FlowSpec:
    """
    'flow' option.

    role: 'to_server' | 'to_client' | None (not constrained).
    state: 'established' | 'not_established' | None (not constrained).
    """
    role: Optional[FlowRole] = None
    state: Optional[FlowStateSpec] = None

    def __post_init__(self) -> None:
        _require(self.role is None or self.role in FLOW_ROLES, f"invalid flow role: {self.role!r}")
        _require(self.state is None or self.state in FLOW_STATES, f"invalid flow state: {self.state!r}")


@dataclass(frozen=True)
class FlagsSpec:
    """
    'flags' option.

    mode: 'exact' (flags set is exactly `flags`) | 'all' (+, all of them set, others free)
          | 'any' (*, at least one set) | 'none' (!, none of them set).
    flags: letters from TCP_FLAG_NAMES. Only mode 'exact' may have an empty set: that is the
          rule 'flags:0' (no flag set at all); the other modes need at least one letter.
    """
    mode: FlagsMode
    flags: frozenset

    def __post_init__(self) -> None:
        _require(self.mode in FLAGS_MODES, f"invalid flags mode: {self.mode!r}")
        _require(all(f in TCP_FLAG_NAMES for f in self.flags), f"invalid TCP flags: {sorted(self.flags)}")
        _require(bool(self.flags) or self.mode == "exact", f"mode {self.mode!r} needs at least one flag")


@dataclass(frozen=True)
class DsizeSpec:
    """
    'dsize' option (payload length in bytes).

    op: 'eq' (== a) | 'lt' (< a) | 'gt' (> a) | 'range' (a <= size <= b).
    a: the operand (lower bound for 'range').
    b: upper bound for 'range'; must be None for the other ops.
    """
    op: DsizeOp
    a: int
    b: Optional[int] = None

    def __post_init__(self) -> None:
        _require(self.op in DSIZE_OPS, f"invalid dsize op: {self.op!r}")
        _require(self.a >= 0, "DsizeSpec.a must be >= 0")
        if self.op == "range":
            _require(self.b is not None and self.b >= self.a, "dsize range needs b >= a")
        else:
            _require(self.b is None, f"DsizeSpec.b must be None for op {self.op!r}")


@dataclass(frozen=True)
class Rule:
    """
    A parsed rule. Data only.

    action: 'alert'.
    protocol: 'tcp' | 'udp' | 'ip'.
    direction: '->' (src to dst only) | '<>' (either way).
    msg/sid/rev/classtype/priority: rule options; msg and sid are required,
        rev defaults to 1, classtype is None when absent. The parser fills priority with
        engine.default_priority when the rule has none, so it is None only on rules built by hand.
    passive_options: options that are only stored and never affect matching (reference,
        metadata, gid), as (key, value) pairs in rule order; empty tuple when none.
    contents: content options in rule order (empty tuple when none).
    flow/flags/dsize: None when the option is absent.
    source_file/line_no: where the rule was read from (line_no is 1-based).
    raw: the rule line verbatim, for reports and the oral defence.
    """
    action: RuleAction
    protocol: RuleProtocol
    src_ip: IpSpec
    src_port: PortSpec
    direction: RuleDirection
    dst_ip: IpSpec
    dst_port: PortSpec
    msg: str
    sid: int
    rev: int = 1
    classtype: Optional[str] = None
    priority: Optional[int] = None
    contents: Tuple[ContentSpec, ...] = ()
    flow: Optional[FlowSpec] = None
    flags: Optional[FlagsSpec] = None
    dsize: Optional[DsizeSpec] = None
    passive_options: Tuple[Tuple[str, Optional[str]], ...] = ()
    source_file: str = ""
    line_no: int = 0
    raw: str = ""

    def __post_init__(self) -> None:
        _require(self.action in RULE_ACTIONS, f"invalid action: {self.action!r}")
        _require(self.protocol in RULE_PROTOCOLS, f"invalid protocol: {self.protocol!r}")
        _require(self.direction in RULE_DIRECTIONS, f"invalid direction: {self.direction!r}")
        _require(self.priority is None or self.priority >= 1, "priority must be >= 1")
