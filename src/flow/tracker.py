import logging
import math
from typing import Any, Callable, List, Optional, Tuple

from src.models.flow import Flow
from src.flow.flow_key import make_key, direction_of, make_flow_id
from src.flow.flow_table import FlowTable, FlowEntry
from src.flow.tcp_state import next_state, normalize_flags
from src.flow.timeout import is_expired, get_close_reason
from src.utils.safe import safe_stage

logger = logging.getLogger(__name__)

DEFAULT_SWEEP_INTERVAL_SEC = 1.0  # must match settings.yaml (flow.sweep_interval_sec)


def _get_sweep_interval(flow_cfg: Any) -> float:
    """Read a positive finite sweep_interval_sec from flow_cfg, else default."""
    v = flow_cfg.get("sweep_interval_sec") if isinstance(flow_cfg, dict) else None
    if type(v) in (int, float) and math.isfinite(v) and v > 0:
        return float(v)
    return DEFAULT_SWEEP_INTERVAL_SEC


class FlowTracker:
    def __init__(self, cfg: Any, on_export: Optional[Callable[[Flow], None]] = None):
        """
        Initializes the FlowTracker.
        """
        self.cfg = cfg if isinstance(cfg, dict) else {}
        self.on_export = on_export
        self.table = FlowTable()
        self.clock: float = 0.0
        self.last_sweep: Optional[float] = None

    def active_flow_count(self) -> int:
        """Returns the number of currently active flows in the table."""
        return len(self.table)

    def _get_flow_cfg(self) -> dict:
        """Safely extracts the 'flow' configuration dictionary."""
        raw_flow_cfg = self.cfg.get("flow", {})
        return raw_flow_cfg if isinstance(raw_flow_cfg, dict) else {}

    def sweep(self, now: Optional[float] = None) -> int:
        """
        Scans the entire active flow table (O(n)), exports all expired flows,
        and removes them from the active table.

        Args:
            now: Event-time timestamp to evaluate expiration against.
                 Defaults to self.clock if not provided or invalid.

        Returns:
            The number of expired flows exported during this sweep.
        """
        if type(now) in (int, float) and math.isfinite(now):
            eval_time = float(now)
        else:
            eval_time = self.clock

        flow_cfg = self._get_flow_cfg()

        # Collect expired entries first before mutating the underlying table
        expired_list: List[Tuple[FlowEntry, str]] = []
        for _key, entry in self.table.items():
            if is_expired(entry, eval_time, flow_cfg):
                expired_list.append((entry, get_close_reason(entry)))

        for entry, reason in expired_list:
            self._export_flow(entry, reason)

        self.last_sweep = min(eval_time, self.clock)  # a far-future manual "now" must not stall periodic sweeps
        return len(expired_list)

    @safe_stage("flow_tracker", event_index=1)
    def update(self, event: Any) -> Any:
        """
        Processes a single IDSEvent to route it to the correct Flow, tracking
        direction, establishing new flows, maintaining the LRU table,
        updating flow statistics & TCP states, and triggering periodic sweeps.
        """
        ts = getattr(event, "timestamp", None)
        ts_ok = type(ts) in (int, float) and math.isfinite(ts)
        
        prep_status = getattr(event, "preprocess_status", None)
        trans_proto = str(getattr(event, "transport_protocol", "")).upper()
        src_ip = getattr(event, "src_ip", None)
        dst_ip = getattr(event, "dst_ip", None)
        src_port = getattr(event, "src_port", None)
        dst_port = getattr(event, "dst_port", None)

        if (
            prep_status == "invalid" or 
            not ts_ok or
            trans_proto not in ("TCP", "UDP") or 
            src_ip is None or dst_ip is None or 
            src_port is None or dst_port is None
        ):
            event.flow_id = None
            event.direction = None
            event.flow_state = None
            return event
            
        # 1. Update internal event-time clock watermark
        ts = float(ts)
        self.clock = max(self.clock, ts)

        flow_cfg = self._get_flow_cfg()

        # 2. Key Generation & Table Lookup
        key = make_key(trans_proto, src_ip, src_port, dst_ip, dst_port)
        entry = self.table.get(key)

        # Extract flags early for port reuse detection and state machine reuse
        t_fields = getattr(event, "transport_fields", None)
        flags = t_fields.get("flags") if isinstance(t_fields, dict) else []
        flag_set = normalize_flags(flags)

        # 3. Lazy Expiration & Port Reuse Detection
        if entry is not None:
            # 3.1 Lazy expiration: check if the existing flow timed out before this packet arrived
            if is_expired(entry, ts, flow_cfg):
                self._export_flow(entry, get_close_reason(entry))
                entry = None
            # 3.2 Port reuse: pure SYN (no ACK) arriving on an unexpired CLOSED/RESET flow
            elif trans_proto == "TCP" and "SYN" in flag_set and "ACK" not in flag_set and entry.flow.state in ("CLOSED", "RESET"):
                self._export_flow(entry, "port_reuse")
                entry = None

        # 4. Attach or Create Flow
        if entry is None:
            flow = Flow(
                flow_id=make_flow_id(key, ts),
                protocol=trans_proto,
                application_protocol=None, 
                endpoint_a={"ip": src_ip, "port": src_port},
                endpoint_b={"ip": dst_ip, "port": dst_port},
                start_time=ts,
                last_seen=ts,
                packet_count=0,
                byte_count=0,
                payload_byte_count=0,
                fwd_packet_count=0,
                fwd_byte_count=0,
                bwd_packet_count=0,
                bwd_byte_count=0,
                syn_count=0,
                ack_count=0,
                fin_count=0,
                rst_count=0,
                state="ACTIVE" if trans_proto == "UDP" else "HANDSHAKE",
                close_reason=None,
                midstream=False
            )
            entry = FlowEntry(flow)
            self.table.add(key, entry)
        else:
            self.table.touch(key)

        # 5. Determine Direction and tag Event
        direction = direction_of(entry.flow.endpoint_a, src_ip, src_port)
        event.flow_id = entry.flow.flow_id
        event.direction = direction

        # 6. TCP State Machine Integration (BEFORE packet_count increment)
        is_first_packet = (entry.flow.packet_count == 0)
        
        if trans_proto == "TCP":
            ctx = {
                "synack_seen": entry.synack_seen,
                "synack_dir": entry.synack_dir,
                "fin_fwd": entry.fin_fwd,
                "fin_bwd": entry.fin_bwd,
                "midstream": entry.flow.midstream,
                "tcp_close_requires_final_ack": bool(flow_cfg.get("tcp_close_requires_final_ack", False))
            }
            
            old_state = entry.flow.state
            new_state = next_state(
                current_state=old_state, 
                flags=list(flag_set),
                direction=direction, 
                ctx=ctx, 
                is_first_packet=is_first_packet
            )
            
            # Synchronize context back
            entry.synack_seen = ctx.get("synack_seen", False)
            entry.synack_dir = ctx.get("synack_dir")
            entry.fin_fwd = ctx.get("fin_fwd", False)
            entry.fin_bwd = ctx.get("fin_bwd", False)
            entry.flow.midstream = ctx.get("midstream", False)
            
            if new_state != old_state:
                entry.flow.state = new_state
                entry.state_changed_at = ts
                
            event.flow_state = new_state
        else:
            event.flow_state = entry.flow.state

        # 7. Update Flow Statistics
        flow = entry.flow
        
        flow.start_time = min(flow.start_time, ts)
        flow.last_seen = max(flow.last_seen, ts)
        
        raw_len = getattr(event, "raw_length", 0)
        if type(raw_len) is not int or raw_len < 0:
            raw_len = 0
            
        payload_bytes = getattr(event, "payload", None)
        payload_len = len(payload_bytes) if isinstance(payload_bytes, bytes) else 0

        flow.packet_count += 1
        flow.byte_count += raw_len
        flow.payload_byte_count += payload_len

        if direction == "forward":
            flow.fwd_packet_count += 1
            flow.fwd_byte_count += raw_len
        else:
            flow.bwd_packet_count += 1
            flow.bwd_byte_count += raw_len

        # 7.4 TCP Flag Counters
        if trans_proto == "TCP":
            if "SYN" in flag_set:
                flow.syn_count += 1
            if "ACK" in flag_set:
                flow.ack_count += 1
            if "FIN" in flag_set:
                flow.fin_count += 1
            if "RST" in flag_set:
                flow.rst_count += 1
            
        # 7.5 Application Protocol Resolution (Specific > UNKNOWN > None)
        event_app = getattr(event, "app_protocol", None)
        if event_app is not None:
            event_app_upper = str(event_app).upper()
            curr_app = flow.application_protocol
            
            if curr_app is None or (curr_app == "UNKNOWN" and event_app_upper != "UNKNOWN"):
                flow.application_protocol = event_app_upper

        # 8. Periodic Sweep Trigger (Event-Time Watermark based)
        sweep_interval = _get_sweep_interval(flow_cfg)
        if self.last_sweep is None:
            self.last_sweep = self.clock
        elif (self.clock - self.last_sweep) >= sweep_interval:
            self.sweep(self.clock)

        return event

    def _export_flow(self, entry: FlowEntry, reason: str) -> None:
        """
        Finalizes a flow, removes it from the active table, and triggers the export callback safely.
        """
        key = make_key(
            entry.flow.protocol,
            entry.flow.endpoint_a["ip"],
            entry.flow.endpoint_a["port"],
            entry.flow.endpoint_b["ip"],
            entry.flow.endpoint_b["port"]
        )
        
        removed_entry = self.table.remove(key)
        if removed_entry is None:
            return  
            
        flow = removed_entry.flow
        flow.close_reason = reason
        
        if self.on_export:
            try:
                self.on_export(flow)
            except Exception as e:
                logger.warning("Flow export callback failed for %s: %s", flow.flow_id, e)