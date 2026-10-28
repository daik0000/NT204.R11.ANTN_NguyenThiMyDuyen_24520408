from typing import Dict, List, Optional, Tuple

from src.models.rule import PORT_MAX, PORT_MIN, PortSpec, Rule
from src.rules.repository import RuleRepository

INDEXED_PROTOCOLS = ("tcp", "udp", "ip")


class _Bucket:
    """Rules of one protocol, split by how their port is written."""

    def __init__(self) -> None:
        self.exact: Dict[int, List[int]] = {}               # single port -> orders
        self.ranges: List[Tuple[int, int, int]] = []        # (lo, hi, order)
        self.any_port: List[int] = []                       # orders

    def register(self, port: PortSpec, order: int) -> None:
        if port.is_any:
            self.any_port.append(order)
        elif port.lo == port.hi:
            self.exact.setdefault(port.lo, []).append(order)
        else:
            self.ranges.append((port.lo, port.hi, order))

    def collect(self, port: int, into: set) -> None:
        into.update(self.exact.get(port, ()))
        into.update(order for lo, hi, order in self.ranges if lo <= port <= hi)
        into.update(self.any_port)


class RuleIndexer:
    """
    Picks candidate rules for a packet from its protocol and destination port, so the engine does
    not walk every rule for every packet.

    Built once from a FROZEN RuleRepository (raises ValueError otherwise): the index cannot go
    stale because the repository cannot change.

    Registration, per rule, in the bucket of its protocol (tcp, udp or ip):
    - '->' rules are filed under the rule's destination port;
    - '<>' rules are filed under BOTH the rule's source port and its destination port, because a
      packet travelling the other way matches the rule through the other side. Filing only the
      destination port would silently miss those packets.
    A port is filed as exact (single port), range (linear scan; an interval tree would be the
    improvement) or any.

    The index is a coarse, superset filter. It looks at nothing but protocol and destination port:
    not IPs, not the rule's source port for '->' rules, not flags or content. A rule it drops can
    never match; a rule it returns still has to pass the matching engine.
    """

    def __init__(self, repository: RuleRepository) -> None:
        if not repository.frozen:
            raise ValueError("RuleIndexer needs a frozen RuleRepository; call freeze() first")
        self._rules: Tuple[Rule, ...] = repository.all()      # index in this tuple == order
        self._buckets: Dict[str, _Bucket] = {p: _Bucket() for p in INDEXED_PROTOCOLS}
        for order, rule in enumerate(self._rules):
            bucket = self._buckets[rule.protocol]
            bucket.register(rule.dst_port, order)
            if rule.direction == "<>":
                bucket.register(rule.src_port, order)

    def __len__(self) -> int:
        return len(self._rules)

    def candidates(self, protocol: Optional[str], dst_port: Optional[int]) -> List[Rule]:
        """
        Rules that might match a packet of `protocol` ('tcp'/'udp', any letter case) going to
        `dst_port`: the protocol's bucket together with the 'ip' bucket, without duplicates and in
        repository order.

        An unknown protocol, or a port that is not an int in 0..65535, gives [] (never raises).
        So an event without a port (ICMP, ARP, no transport layer) has no candidates, and 'ip'
        rules only apply to TCP/UDP packets here.

        Looking up protocol 'ip' returns the 'ip' bucket alone: a real packet is never of
        protocol 'ip', this form exists only to inspect that bucket.
        """
        if not isinstance(protocol, str) or protocol.lower() not in INDEXED_PROTOCOLS:
            return []
        if isinstance(dst_port, bool) or not isinstance(dst_port, int) or not PORT_MIN <= dst_port <= PORT_MAX:
            return []

        name = protocol.lower()
        orders: set = set()
        self._buckets[name].collect(dst_port, orders)
        if name != "ip":
            self._buckets["ip"].collect(dst_port, orders)
        return [self._rules[o] for o in sorted(orders)]
