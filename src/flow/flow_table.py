from collections import OrderedDict
from typing import Any, Optional, Tuple, List
from src.models.flow import Flow

class FlowEntry:
    """
    A wrapper around the Flow dataclass that holds internal tracking state.
    These internal fields are crucial for state machine logic (e.g., TCP)
    but must NOT be exported to the final flows.jsonl log.
    """
    def __init__(self, flow: Flow):
        self.flow = flow
        
        # Internal tracker fields (State Machine tracking)
        self.fin_fwd: bool = False
        self.fin_bwd: bool = False
        self.synack_seen: bool = False
        self.synack_dir: Optional[str] = None   # direction of the SYN/ACK; the opposite side completes the handshake
        self.state_changed_at: float = flow.start_time


class FlowTable:
    """
    An active flow table using OrderedDict to maintain an O(1) LRU cache.
    The most recently updated flows are moved to the end.
    The oldest (least recently active) flows remain at the beginning for O(1) eviction.
    """
    def __init__(self):
        self._table: OrderedDict[Any, FlowEntry] = OrderedDict()

    def get(self, key: Any) -> Optional[FlowEntry]:
        """Retrieves a flow entry without changing its LRU position."""
        return self._table.get(key)

    def add(self, key: Any, entry: FlowEntry) -> None:
        """Adds a new flow entry and marks it as the most recently active."""
        self._table[key] = entry
        self._table.move_to_end(key)

    def touch(self, key: Any) -> None:
        """Moves an existing flow to the end, marking it as most recently active (O(1))."""
        if key in self._table:
            self._table.move_to_end(key)

    def remove(self, key: Any) -> Optional[FlowEntry]:
        """Removes and returns the flow entry if it exists."""
        return self._table.pop(key, None)

    def __len__(self) -> int:
        return len(self._table)

    def __contains__(self, key: Any) -> bool:
        """Supports the 'key in table' operator."""
        return key in self._table

    def items(self) -> List[Tuple[Any, FlowEntry]]:
        """Return a snapshot of (key, entry) pairs; safe to remove entries while iterating."""
        return list(self._table.items())

    def oldest(self) -> Optional[Tuple[Any, FlowEntry]]:
        """
        Returns the (key, FlowEntry) of the least recently active flow (O(1)).
        Returns None if the table is empty.
        """
        if not self._table:
            return None
        
        oldest_key = next(iter(self._table))
        return oldest_key, self._table[oldest_key]