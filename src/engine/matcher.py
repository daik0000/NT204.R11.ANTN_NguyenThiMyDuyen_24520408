import ipaddress
from typing import Any, Optional

from src.models.rule import IpSpec, PortSpec, Rule


def _ip_to_int(value: Any) -> Optional[int]:
    """IPv4 address text as an integer, or None if it is not a valid IPv4 address string."""
    if not isinstance(value, str):
        return None
    try:
        return int(ipaddress.IPv4Address(value))
    except ValueError:
        return None


def _ip_in(spec: IpSpec, ip: int) -> bool:
    return spec.any or (ip & spec.mask) == spec.network


def _port_in(spec: PortSpec, port: int) -> bool:
    return spec.lo <= port <= spec.hi


def _valid_port(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= 65535


def match_header(rule: Rule, event: Any) -> bool:
    """
    Does the packet fit the rule header (protocol, addresses, ports, direction)? Never raises.

    - protocol: a 'tcp' or 'udp' rule needs the same transport protocol; an 'ip' rule accepts any
      TCP or UDP packet. An event with another or no transport protocol never matches.
    - '->': the packet's source must fit the rule's source (IP and port) and its destination the
      rule's destination.
    - '<>': the forward test above, or the reversed one. Reversed means the packet's source is
      compared with the rule's DESTINATION and the packet's destination with the rule's SOURCE,
      IP and port together; the two sides are never mixed (a packet with the rule's source IP but
      the rule's destination port matches neither way).
    - An event whose IPs are not valid IPv4 strings, or whose ports are not ints in 0..65535, does
      not match (False), it does not raise, not even for an 'any any' rule: corrupt data never matches.
      Each IP is converted to an integer once per call (so once per rule tested, see the README).

    Only the header is checked; flags, flow, dsize and content are other stages.
    """
    protocol = getattr(event, "transport_protocol", None)
    protocol = protocol.lower() if isinstance(protocol, str) else None
    if protocol not in ("tcp", "udp"):
        return False
    if rule.protocol != "ip" and rule.protocol != protocol:
        return False

    src_port, dst_port = getattr(event, "src_port", None), getattr(event, "dst_port", None)
    if not (_valid_port(src_port) and _valid_port(dst_port)):
        return False
    src_ip, dst_ip = _ip_to_int(getattr(event, "src_ip", None)), _ip_to_int(getattr(event, "dst_ip", None))
    if src_ip is None or dst_ip is None:
        return False

    if (_ip_in(rule.src_ip, src_ip) and _port_in(rule.src_port, src_port)
            and _ip_in(rule.dst_ip, dst_ip) and _port_in(rule.dst_port, dst_port)):
        return True
    if rule.direction == "<>":
        return (_ip_in(rule.dst_ip, src_ip) and _port_in(rule.dst_port, src_port)
                and _ip_in(rule.src_ip, dst_ip) and _port_in(rule.src_port, dst_port))
    return False
