from dataclasses import asdict, dataclass
from typing import Dict

from src.models.engine_types import FAILED_STAGES


@dataclass
class EvaluationStats:
    """
    Counters for one run of the rule engine, to prove with numbers how many rules were thrown out
    before the expensive content search (T07).

    events_evaluated        events the engine tested against rules
    events_skipped          events the engine did not test: the engine is disabled, there are no
                            rules, or the event is not eligible (processing_action skipped/dropped,
                            preprocess_status invalid, no usable transport protocol)
    candidate_rules         candidates returned by the Indexer, summed over all evaluated events
    rules_rejected_header   candidates that failed the header stage
    rules_rejected_flow     ... failed the flow stage
    rules_rejected_packet   ... failed the packet stage (flags / dsize)
    content_evaluations     times the content stage RAN TO COMPLETION (matched or not): a rule that
                            passed header, flow and packet and had content to search. A rule
                            rejected earlier, a header-only rule, or a rule whose content search
                            raised an exception never adds to it
    rules_rejected_content  content stage completed and did not match
    matches                 candidates that matched completely (a Detection each)
    rule_errors             candidates whose evaluation raised an exception (isolated, then skipped);
                            such a rule counts here only, never in a stage counter or in matches

    Every candidate ends in exactly one outcome, so after a run:
        candidate_rules == rules_rejected_header + rules_rejected_flow + rules_rejected_packet
                           + rules_rejected_content + matches + rule_errors
    (is_consistent() checks this), and
        content_evaluations == rules_rejected_content + (matches of rules that have content).
    The engine must call record_rule_error() exactly once for a failing rule and record_match()
    only for a rule that matched.

    match_rule feeds the stage counters through record_stage(); the engine feeds the others.
    """
    events_evaluated: int = 0
    events_skipped: int = 0
    candidate_rules: int = 0
    rules_rejected_header: int = 0
    rules_rejected_flow: int = 0
    rules_rejected_packet: int = 0
    content_evaluations: int = 0
    rules_rejected_content: int = 0
    matches: int = 0
    rule_errors: int = 0

    def record_stage(self, stage: str, passed: bool) -> None:
        """Called by match_rule once for each stage it actually evaluated."""
        if stage not in FAILED_STAGES:
            raise ValueError(f"unknown stage: {stage!r}")
        if stage == "content":
            self.content_evaluations += 1
            if not passed:
                self.rules_rejected_content += 1
        elif not passed:
            setattr(self, f"rules_rejected_{stage}", getattr(self, f"rules_rejected_{stage}") + 1)

    def record_event_evaluated(self, candidates: int) -> None:
        """One event was tested against `candidates` candidate rules (0 is allowed)."""
        if candidates < 0:
            raise ValueError("candidates must be >= 0")
        self.events_evaluated += 1
        self.candidate_rules += candidates

    def record_event_skipped(self) -> None:
        self.events_skipped += 1

    def record_match(self) -> None:
        self.matches += 1

    def record_rule_error(self) -> None:
        self.rule_errors += 1

    def is_consistent(self) -> bool:
        """True if the outcome equation in the class docstring holds (for a warning at the end of a run)."""
        return self.candidate_rules == (self.rules_rejected_header + self.rules_rejected_flow
                                        + self.rules_rejected_packet + self.rules_rejected_content
                                        + self.matches + self.rule_errors)

    def to_dict(self) -> Dict[str, int]:
        return asdict(self)

    def summary(self) -> str:
        """One line for the log at the end of a run."""
        return ("engine: "
                f"events_evaluated={self.events_evaluated} events_skipped={self.events_skipped} "
                f"candidate_rules={self.candidate_rules} "
                f"rejected_header={self.rules_rejected_header} rejected_flow={self.rules_rejected_flow} "
                f"rejected_packet={self.rules_rejected_packet} "
                f"content_evaluations={self.content_evaluations} rejected_content={self.rules_rejected_content} "
                f"matches={self.matches} rule_errors={self.rule_errors}")
