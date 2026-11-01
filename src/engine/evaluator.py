import logging
from typing import Any, Dict, List, Optional

from src.engine.content_matcher import match_contents
from src.engine.detection import make_detection
from src.engine.matcher import match_rule
from src.engine.stats import EvaluationStats
from src.models.detection import Detection
from src.models.engine_types import FlowContext, MatchResult
from src.rules.indexer import RuleIndexer
from src.rules.repository import RuleRepository

logger = logging.getLogger(__name__)

# processing_action values (set by the Preprocessor) of events that never reach the engine.
SKIPPED_ACTIONS = ("skipped", "dropped")


class EvaluationEngine:
    """
    Tests one event against every candidate rule and returns all the rules that match.

    The repository is frozen (idempotent) and indexed here, once. evaluate() then asks the index for
    the candidates of the packet's protocol and destination port, runs match_rule on EACH of them,
    and keeps every complete match, in repository (rule file) order. It does not stop at the first
    match: one packet can trigger several rules.

    Each rule is isolated: an exception while testing a rule is counted (stats.rule_errors), logged
    as a warning and the next rule is tested. Only Exception is caught, so KeyboardInterrupt and
    SystemExit still stop the program. The full warning (with traceback) is written once per sid;
    later failures of the same rule are only logged at debug level, but rule_errors counts every one.

    What the engine does NOT isolate is an error at event level (reading the event, the index lookup):
    the pipeline must call evaluate() inside a guarded stage (@safe_stage, as in Part 2).

    events_skipped is counted here and only here: the pipeline should call evaluate() for every event
    that leaves the Flow Tracker and let the engine decide. Events whose status is IGNORED (the
    unknown_policy skip: it only decides whether the event is logged) or whose application protocol is
    UNKNOWN are still evaluated, since their transport header and payload are intact.
    """

    def __init__(self, repository: RuleRepository, stats: Optional[EvaluationStats] = None,
                 cfg: Optional[Dict[str, Any]] = None) -> None:
        repository.freeze()
        self._repository = repository
        self._indexer = RuleIndexer(repository)
        self.stats = stats if stats is not None else EvaluationStats()
        engine_cfg = cfg.get("engine") if isinstance(cfg, dict) else None
        # load_config already checks that engine.enabled is a real bool
        self._enabled = bool(engine_cfg.get("enabled", True)) if isinstance(engine_cfg, dict) else True
        self._warned_sids: set = set()

    @property
    def enabled(self) -> bool:
        return self._enabled

    def evaluate(self, event: Any, flow_ctx: Optional[FlowContext]) -> List[MatchResult]:
        """
        Match `event` (whose flow context is `flow_ctx`, None if it has none) against the rules.

        Returns the matched MatchResults in rule order; [] when nothing matched or the event was
        skipped. An event is skipped, and counted in stats.events_skipped, when the engine is
        disabled, there are no rules, or the event is not eligible: processing_action skipped or
        dropped, preprocess_status invalid, or no TCP/UDP transport protocol and ports. Never
        raises for a failing rule. A match is counted (stats.matches) as soon as the rule matches.
        """
        return self._run(event, flow_ctx, lambda rule, result: result)

    def detect(self, event: Any, flow_ctx: Optional[FlowContext]) -> List[Detection]:
        """
        Like evaluate(), but returns the Detection Events, in rule order. This is what the pipeline
        calls.

        For each rule the steps match_rule -> make_detection -> record_match run in ONE guarded
        block, so a rule counts as a match only when its Detection was really built. An error while
        building it (a bad event, say) is counted as a rule error and never as a match: stats.matches
        always equals the number of Detections returned, summed over the run.
        """
        return self._run(event, flow_ctx,
                         lambda rule, result: make_detection(rule, event, flow_ctx, result.matches))

    def _run(self, event: Any, flow_ctx: Optional[FlowContext], build) -> list:
        """Shared loop of evaluate() and detect(); build(rule, result) makes what is returned per match."""
        if not self._enabled or len(self._repository) == 0 or not self._eligible(event):
            self.stats.record_event_skipped()
            return []

        candidates = self._indexer.candidates(event.transport_protocol, event.dst_port)
        self.stats.record_event_evaluated(len(candidates))
        content_fn = self._content_fn_for(event)

        matched: list = []
        for rule in candidates:
            try:
                result = match_rule(rule, event, flow_ctx, content_fn, self.stats)
                if result.matched:
                    item = build(rule, result)               # may raise: then it is a rule error
                    self.stats.record_match()
                    matched.append(item)
            except Exception:                    # not BaseException: Ctrl+C must still stop us
                self.stats.record_rule_error()
                sid = getattr(rule, "sid", "?")
                if sid not in self._warned_sids:
                    self._warned_sids.add(sid)
                    logger.warning("rule sid=%s failed on packet %s and is skipped for this packet "
                                   "(further failures of this rule are logged at debug level only)",
                                   sid, getattr(event, "packet_id", "?"), exc_info=True)
                else:
                    logger.debug("rule sid=%s failed again on packet %s", sid,
                                 getattr(event, "packet_id", "?"), exc_info=True)
        return matched

    @staticmethod
    def _eligible(event: Any) -> bool:
        if getattr(event, "processing_action", None) in SKIPPED_ACTIONS:
            return False
        if getattr(event, "preprocess_status", None) == "invalid":
            return False
        protocol = getattr(event, "transport_protocol", None)
        if not isinstance(protocol, str) or protocol.lower() not in ("tcp", "udp"):
            return False
        port = getattr(event, "dst_port", None)
        return isinstance(port, int) and not isinstance(port, bool)

    @staticmethod
    def _content_fn_for(event: Any):
        """
        A content_fn for this packet that converts the payload to bytes once and lower-cases it at
        most once (lazily, only if some rule being tested has a nocase content), however many rules
        are tested.
        """
        payload = getattr(event, "payload", None)
        if isinstance(payload, (bytearray, memoryview)):
            payload = bytes(payload)
        cache: Dict[str, Optional[bytes]] = {}

        def content_fn(rule, _event):
            lowered = None
            if isinstance(payload, bytes) and any(c.nocase for c in rule.contents):
                if "lowered" not in cache:
                    cache["lowered"] = payload.lower()
                lowered = cache["lowered"]
            return match_contents(rule, payload, lowered)

        return content_fn
