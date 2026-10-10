import logging
import math
from typing import Any, Callable, Optional

from src.models.flow import Flow
from src.flow.flow_key import make_key, direction_of, make_flow_id
from src.flow.flow_table import FlowTable, FlowEntry
from src.flow.tcp_state import next_state, normalize_flags
from src.utils.safe import safe_stage

logger = logging.getLogger(__name__)

class FlowTracker:
    def __init__(self, cfg: Any, on_export: Optional[Callable[[Flow], None]] = None):
        """
        Initializes the FlowTracker.
        """
        self.cfg = cfg if isinstance(cfg, dict) else {}
        self.on_export = on_export
        self.table = FlowTable()
        self.clock = 0.0  

    @safe_stage("flow_tracker", event_index=1)
    def update(self, event: Any) -> Any:
        """
        Processes a single IDSEvent to route it to the correct Flow, tracking
        direction, establishing new flows, maintaining the LRU table, and
        updating flow statistics & TCP states.
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

        # 2. Key Generation & Table Lookup
        key = make_key(trans_proto, src_ip, src_port, dst_ip, dst_port)
        entry = self.table.get(key)

        # Extract flags early for port reuse detection and state machine reuse
        t_fields = getattr(event, "transport_fields", None)
        flags = t_fields.get("flags") if isinstance(t_fields, dict) else []
        flag_set = normalize_flags(flags)

        # 3. Port Reuse Detection
        # If a pure SYN (no ACK) arrives for an existing flow that is already terminated,
        # we flush the old flow and treat this as a brand new connection.
        if entry is not None and trans_proto == "TCP":
            if "SYN" in flag_set and "ACK" not in flag_set and entry.flow.state in ("CLOSED", "RESET"):
                # CRITICAL: Export the old flow BEFORE creating the new one to prevent
                # _export_flow from accidentally purging the newly created entry via the shared key.
                self._export_flow(entry, "port_reuse")
                entry = None  # Force creation of a new flow below

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
            # Extract tracking config from correct section
            tracker_cfg = self.cfg.get("flow", {})
            
            ctx = {
                "synack_seen": entry.synack_seen,
                "synack_dir": entry.synack_dir,
                "fin_fwd": entry.fin_fwd,
                "fin_bwd": entry.fin_bwd,
                "midstream": entry.flow.midstream,
                "tcp_close_requires_final_ack": tracker_cfg.get("tcp_close_requires_final_ack", False)
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