"""
Types passed between the engine stages (data only, no matching logic).

Enum-like domains (keep the tuple and its Literal in sync; __post_init__ validates
against the tuples):
  FlowContext.protocol  'TCP' | 'UDP'                              (CONTEXT_PROTOCOLS)
  FlowContext.state     'HANDSHAKE' | 'ESTABLISHED' | 'CLOSING' | 'CLOSED' | 'RESET' | 'ACTIVE'
                        (CONTEXT_STATES, same values as Flow.state)
  FlowContext.role      'to_server' | 'to_client' | None           (CONTEXT_ROLES)
  FlowContext.direction 'forward' | 'backward'                     (CONTEXT_DIRECTIONS)
  MatchResult.failed_stage  None | 'header' | 'flow' | 'packet' | 'content'  (FAILED_STAGES)

The stages run in the order header -> flow -> packet -> content; failed_stage is the
first stage that rejected the packet, so it proves a rule was dropped before content
matching.
"""
from dataclasses import dataclass, field
from typing import Any, Dict, List, Literal, Optional

from src.models.rule import Rule

ContextProtocol = Literal["TCP", "UDP"]
CONTEXT_PROTOCOLS = ("TCP", "UDP")

ContextState = Literal["HANDSHAKE", "ESTABLISHED", "CLOSING", "CLOSED", "RESET", "ACTIVE"]
CONTEXT_STATES = ("HANDSHAKE", "ESTABLISHED", "CLOSING", "CLOSED", "RESET", "ACTIVE")

ContextRole = Literal["to_server", "to_client"]
CONTEXT_ROLES = ("to_server", "to_client")

ContextDirection = Literal["forward", "backward"]
CONTEXT_DIRECTIONS = ("forward", "backward")

FailedStage = Literal["header", "flow", "packet", "content"]
FAILED_STAGES = ("header", "flow", "packet", "content")


@dataclass(frozen=True)
class FlowContext:
    """
    What the engine knows about the flow of the packet under test.

    flow_id: id of the flow (Flow.flow_id).
    protocol: 'TCP' | 'UDP'.
    state: flow state right after this packet (IDSEvent.flow_state).
    role: role of THIS packet's sender: 'to_server' | 'to_client' | None when unknown.
          It is not the forward/backward direction.
    established: precomputed by the engine so the matcher only reads it:
          TCP -> the state after this packet is ESTABLISHED, CLOSING or CLOSED;
          UDP -> at least one packet in the reverse direction has been seen, including this one.
          HANDSHAKE and RESET are not established. (UDP does not use `state`, which is always ACTIVE.)
    midstream: the flow was first seen mid-connection (no handshake observed).
    direction: 'forward' | 'backward' (IDSEvent.direction, relative to the flow's endpoint A).

    Protocol/state pairing: UDP flows are always 'ACTIVE'; TCP flows never are.
    """
    flow_id: str
    protocol: ContextProtocol
    state: ContextState
    role: Optional[ContextRole]
    established: bool
    midstream: bool
    direction: ContextDirection

    def __post_init__(self) -> None:
        if self.protocol not in CONTEXT_PROTOCOLS:
            raise ValueError(f"invalid protocol: {self.protocol!r}")
        if self.state not in CONTEXT_STATES:
            raise ValueError(f"invalid state: {self.state!r}")
        if (self.protocol == "UDP") != (self.state == "ACTIVE"):
            raise ValueError(f"state {self.state!r} does not fit protocol {self.protocol!r}")
        if self.role is not None and self.role not in CONTEXT_ROLES:
            raise ValueError(f"invalid role: {self.role!r}")
        if self.direction not in CONTEXT_DIRECTIONS:
            raise ValueError(f"invalid direction: {self.direction!r}")
        if not isinstance(self.established, bool) or not isinstance(self.midstream, bool):
            raise ValueError("established and midstream must be bool")


@dataclass(frozen=True)
class MatchResult:
    """
    Outcome of testing one rule against one packet.

    matched: True if every stage passed.
    rule: the rule that was tested.
    failed_stage: None when matched; otherwise the first stage that rejected the packet
                  ('header' | 'flow' | 'packet' | 'content').
    matches: details for the Detection, same element format as Detection.matched. Non-empty
             when matched is True (a rule without content gets [{"keyword": "header"}], filled
             by the matcher), empty otherwise.
    """
    matched: bool
    rule: Rule
    failed_stage: Optional[FailedStage] = None
    matches: List[Dict[str, Any]] = field(default_factory=list)

    def __post_init__(self) -> None:
        if not isinstance(self.matched, bool):
            raise ValueError("matched must be bool")
        if self.failed_stage is not None and self.failed_stage not in FAILED_STAGES:
            raise ValueError(f"invalid failed_stage: {self.failed_stage!r}")
        if self.matched and self.failed_stage is not None:
            raise ValueError("a matched result cannot have a failed_stage")
        if not self.matched and self.failed_stage is None:
            raise ValueError("an unmatched result needs a failed_stage")
        if self.matched and not self.matches:
            raise ValueError("a matched result needs at least one element in matches")
        if not self.matched and self.matches:
            raise ValueError("an unmatched result cannot carry matches")
