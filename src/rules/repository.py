from typing import Dict, Iterator, List, Optional, Tuple

from src.models.rule import Rule


class RuleRepository:
    """
    Stores the validated rules in the order they were added, which is the order they appear in
    the rule files. That order is the contract behind "detections come out in rule order" (T13),
    so rules live in a list, never in a set.

    Each rule gets an order number 0, 1, 2, ... in the order of add(). Rule is frozen, so the
    number is kept here (order_of) and not on the rule.

    After the load, call freeze(): from then on add() raises, so an index built from the
    repository cannot go stale. Call it once, right after loading and before building the index.
    Per-packet code must go through the index (candidates), not through all().
    """

    def __init__(self) -> None:
        self._rules: List[Rule] = []
        self._by_sid: Dict[int, Tuple[int, Rule]] = {}
        self._frozen = False
        self._snapshot: Optional[Tuple[Rule, ...]] = None     # set by freeze()

    def add(self, rule: Rule) -> int:
        """
        Append `rule` and return its order number.

        Raises RuntimeError if the repository is frozen, and ValueError if its sid is already
        stored (the Loader reports duplicates as invalid before they get here, so this is a
        safety net).
        """
        if self._frozen:
            raise RuntimeError("RuleRepository is frozen; no more rules can be added")
        if rule.sid in self._by_sid:
            raise ValueError(f"duplicate sid {rule.sid}")
        order = len(self._rules)
        self._rules.append(rule)
        self._by_sid[rule.sid] = (order, rule)
        return order

    def _entry(self, sid: object) -> Optional[Tuple[int, Rule]]:
        try:
            return self._by_sid.get(sid)
        except TypeError:                    # unhashable key such as [] or {}: not a sid
            return None

    def get(self, sid: int) -> Optional[Rule]:
        """The rule with this sid, or None."""
        entry = self._entry(sid)
        return entry[1] if entry else None

    def order_of(self, sid: int) -> Optional[int]:
        """Order number of the rule with this sid (0 = first added), or None."""
        entry = self._entry(sid)
        return entry[0] if entry else None

    def all(self) -> Tuple[Rule, ...]:
        """
        Every rule, in the order added, as a tuple that does not change afterwards. Before
        freeze() a new tuple is built on each call (O(n)); after freeze() the same one is returned.
        """
        if self._snapshot is not None:
            return self._snapshot
        return tuple(self._rules)

    def freeze(self) -> None:
        """Forbid further add() calls. Calling it again is harmless."""
        if not self._frozen:
            self._snapshot = tuple(self._rules)
        self._frozen = True

    @property
    def frozen(self) -> bool:
        return self._frozen

    def __len__(self) -> int:
        return len(self._rules)

    def __iter__(self) -> Iterator[Rule]:
        """Iterate over a snapshot (like all()), so add() during a loop does not disturb it."""
        return iter(self.all())

    def __contains__(self, sid: object) -> bool:
        return self._entry(sid) is not None
