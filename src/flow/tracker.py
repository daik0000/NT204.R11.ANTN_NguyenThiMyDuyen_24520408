import logging
import math
from typing import Any, Callable, Optional
from src.models.flow import Flow
from src.flow.flow_key import make_key, direction_of, make_flow_id
from src.flow.flow_table import FlowTable, FlowEntry
from src.utils.safe import safe_stage

logger = logging.getLogger(__name__)

class FlowTracker:
    def __init__(self, cfg: Any, on_export: Optional[Callable[[Flow], None]] = None):
        """
        Initializes the FlowTracker.
        """
        self.cfg = cfg
        self.on_export = on_export
        self.table = FlowTable()
        self.clock = 0.0  

    @safe_stage("flow_tracker", event_index=1)
    def update(self, event: Any) -> Any:
        """
        Processes a single IDSEvent to route it to the correct Flow, tracking
        direction, establishing new flows, maintaining the LRU table, and
        updating flow statistics.
        """
        ts = getattr(event, "timestamp", None)
        ts_ok = type(ts) in (int, float) and math.isfinite(ts)
        
        prep_status = getattr(event, "preprocess_status", None)
        trans_proto = str(getattr(event, "transport_protocol", "")).upper()
        src_ip = getattr(event, "src_ip", None)
        dst_ip = getattr(event, "dst_ip", None)
        src_port = getattr(event, "src_port", None)
        dst_port = getattr(event, "dst_port", None)

        # Skip if event is invalid, malformed, missing 5-tuple, or has infinite timestamp.
        if (
            prep_status == "invalid" or 
            not ts_ok or
            trans_proto not in ("TCP", "UDP") or 
            src_ip is None or dst_ip is None or 
            src_port is None or dst_port is None
        ):
            event.flow_id = None
            event.direction = None
            return event
            
        # 1. Update internal event-time clock watermark using valid timestamps only
        ts = float(ts)
        self.clock = max(self.clock, ts)

        # 2. Key Generation & Table Lookup
        key = make_key(trans_proto, src_ip, src_port, dst_ip, dst_port)
        entry = self.table.get(key)

        # 3. Attach or Create Flow
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
                # UDP defaults to ACTIVE. TCP starts as HANDSHAKE until state machine runs.
                state="ACTIVE" if trans_proto == "UDP" else "HANDSHAKE",
                close_reason=None,
                midstream=False
            )
            entry = FlowEntry(flow)
            self.table.add(key, entry)
        else:
            self.table.touch(key)

        # 4. Determine Direction and tag Event
        direction = direction_of(entry.flow.endpoint_a, src_ip, src_port)
        event.flow_id = entry.flow.flow_id
        event.direction = direction

        # 5. Update Flow Statistics
        flow = entry.flow
        
        # 5.1 Timestamps
        flow.start_time = min(flow.start_time, ts)
        flow.last_seen = max(flow.last_seen, ts)
        
        # 5.2 Safely extract byte counts
        raw_len = getattr(event, "raw_length", 0)
        if type(raw_len) is not int or raw_len < 0:
            raw_len = 0
            
        payload_bytes = getattr(event, "payload", None)
        payload_len = len(payload_bytes) if isinstance(payload_bytes, bytes) else 0

        # 5.3 Increment global and directional counters
        flow.packet_count += 1
        flow.byte_count += raw_len
        flow.payload_byte_count += payload_len

        if direction == "forward":
            flow.fwd_packet_count += 1
            flow.fwd_byte_count += raw_len
        else:
            flow.bwd_packet_count += 1
            flow.bwd_byte_count += raw_len

        # 5.4 TCP Flag Counters (Defensive programming against T06)
        if trans_proto == "TCP":
            t_fields = getattr(event, "transport_fields", None)
            flags = t_fields.get("flags") if isinstance(t_fields, dict) else []
            
            if not isinstance(flags, (list, tuple, set, frozenset)):
                flags = []
                
            flag_set = {str(f).upper() for f in flags}
            
            if "SYN" in flag_set:
                flow.syn_count += 1
            if "ACK" in flag_set:
                flow.ack_count += 1
            if "FIN" in flag_set:
                flow.fin_count += 1
            if "RST" in flag_set:
                flow.rst_count += 1
            
        # 5.5 Application Protocol Resolution (Specific > UNKNOWN > None)
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