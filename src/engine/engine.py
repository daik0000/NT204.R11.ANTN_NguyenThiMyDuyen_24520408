import copy
import functools
import logging
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Union

from src.engine.evaluator import EvaluationEngine
from src.engine.flow_context import build_flow_context
from src.engine.stats import EvaluationStats
from src.models.detection import Detection
from src.models.rule_report import LoadReport, RuleRecord
from src.rules.loader import load_rules
from src.rules.repository import RuleRepository
from src.rules.validator import parse_rule
from src.utils.config import DEFAULT_CONFIG

logger = logging.getLogger(__name__)


def engine_enabled(cfg: Optional[Dict[str, Any]]) -> bool:
    """
    The single place that decides whether the rule engine runs: engine.enabled, true when the engine
    section or the key is missing, or the section is empty (`engine:` with nothing under it).
    """
    section = cfg.get("engine") if isinstance(cfg, dict) else None
    return bool((section if isinstance(section, dict) else {}).get("enabled", True))


class Engine:
    """
    The rule engine as the pipeline sees it: load, index and evaluate behind one object.

    __init__ does the whole set-up once: Loader -> Parser -> Repository (frozen) -> Indexer. It keeps
    the LoadReport (report) and the per-line RuleRecords (records) for rules_report.jsonl. process()
    then turns one event into its Detection Events.

    The engine is always valid: with no rule file, an unreadable file, or only rejected rules, there
    are simply no active rules, process() returns [] and the program runs as it did before Part 3.
    With engine.enabled false the rules are not even loaded (no file is opened, nothing is
    reported) and process() returns [] for every event; --rules files are then ignored with a warning,
    but one that does not exist is still an error.

    cfg is the full config from load_config(); a missing engine section, or missing keys in it, mean
    the defaults.
    tracker is the FlowTracker of the pipeline; it is only READ (snapshot), and may be None, in which
    case no packet has a flow context and rules with flow: never match. extra_rule_paths are the files
    of --rules; a path that is not an existing file raises FileNotFoundError here, before anything runs.
    """

    def __init__(self, cfg: Optional[Dict[str, Any]], tracker: Any = None,
                 extra_rule_paths: Optional[Iterable[Union[str, Path]]] = None) -> None:
        cfg = dict(cfg) if isinstance(cfg, dict) else {}
        user_engine = cfg.get("engine") if isinstance(cfg.get("engine"), dict) else {}
        cfg["engine"] = {**copy.deepcopy(DEFAULT_CONFIG["engine"]), **user_engine}     # missing keys -> defaults
        self._cfg = cfg
        self._tracker = tracker
        self.stats = EvaluationStats()
        self.repository = RuleRepository()
        self.report = LoadReport()
        self.records: List[RuleRecord] = []

        self._enabled = engine_enabled(cfg)
        extras = list(extra_rule_paths) if extra_rule_paths is not None else []
        if not self._enabled and extras:
            for path in extras:                              # a typo is still an error, even if unused
                if not Path(path).is_file():
                    raise FileNotFoundError(f"Rule file not found: {path}")
            logger.warning("--rules ignored because the engine is disabled (engine.enabled: false)")
        if self._enabled:
            rules, self.report, self.records = load_rules(
                cfg, functools.partial(parse_rule, cfg=cfg), extras)
            for rule in rules:
                self.repository.add(rule)        # the Loader already rejected duplicate sids: a ValueError here is a real bug
            logger.info(self.report.summary())
        self._evaluator = EvaluationEngine(self.repository, self.stats, cfg)     # freezes + indexes

    @property
    def enabled(self) -> bool:
        """Whether the engine evaluates events (engine.enabled); read-only."""
        return self._enabled

    @property
    def rule_count(self) -> int:
        """Number of active rules."""
        return len(self.repository)

    def process(self, event: Any) -> List[Detection]:
        """
        The Detection Events of one event, in rule order; [] if nothing matched, the event is not
        eligible, the engine is disabled or no rule is active (the evaluator counts those as skipped).

        Call it after FlowTracker.update(event), so that the flow context describes the state after
        this packet. The tracker is only read. An event with no flow_id (not tracked) gets no flow
        context: rules with flow: do not match it, rules without flow: still can.
        """
        flow_ctx = None
        # An event the Flow Tracker did not track has flow_id None (skipped, dropped, invalid, or the
        # tracker failed on it): it has no flow context, whatever another packet with the same 5-tuple
        # left in the table, so the tracker is not even asked.
        if (self._tracker is not None and self.rule_count and self._evaluator.enabled
                and getattr(event, "flow_id", None) is not None):
            flow = self._tracker.snapshot(event)
            if flow is not None and flow.flow_id == event.flow_id:        # the flow the tracker assigned
                flow_ctx = build_flow_context(event, flow, self._cfg)
        return self._evaluator.detect(event, flow_ctx)

    def summary(self) -> str:
        """Two-part line for the end of a run: rule loading, then evaluation."""
        return f"{self.report.summary()} | {self.stats.summary()}"
