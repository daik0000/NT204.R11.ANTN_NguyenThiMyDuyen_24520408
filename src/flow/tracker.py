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
        
        Args:
            cfg: The configuration dictionary.
            on_export: Callback function triggered when a flow is evicted/exported.
        """
        self.cfg = cfg
        self.on_export = on_export
        self.table = FlowTable()
        self.clock = 0.0  # High-water mark for event-time processing

    @safe_stage("flow_tracker", event_index=1)
    def update(self, event: Any) -> Any:
        """
        Processes a single IDSEvent to route it to the correct Flow, tracking
        direction, establishing new flows, and maintaining the LRU table.
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
            # Create a new Flow dataclass. Counters/states will be updated fully in the next commit.
            flow = Flow(
                flow_id=make_flow_id(key, ts),
                protocol=trans_proto,
                application_protocol=getattr(event, "app_protocol", None),
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
            # Existing flow: Touch it in the LRU cache (O(1)) and update last_seen
            self.table.touch(key)
            if ts > entry.flow.last_seen:
                entry.flow.last_seen = ts

        # 4. Determine Direction and tag Event
        direction = direction_of(entry.flow.endpoint_a, src_ip, src_port)
        event.flow_id = entry.flow.flow_id
        event.direction = direction

        return event

    def _export_flow(self, entry: FlowEntry, reason: str) -> None:
        """
        Finalizes a flow, removes it from the active table, and triggers the export callback safely.
        """
        # Reconstruct the routing key safely to remove it from the OrderedDict
        key = make_key(
            entry.flow.protocol,
            entry.flow.endpoint_a["ip"],
            entry.flow.endpoint_a["port"],
            entry.flow.endpoint_b["ip"],
            entry.flow.endpoint_b["port"]
        )
        
        # Remove from table
        removed_entry = self.table.remove(key)
        if removed_entry is None:
            return  # Safety fallback in case it was already purged
            
        flow = removed_entry.flow
        flow.close_reason = reason
        
        # Trigger export callback safely
        if self.on_export:
            try:
                self.on_export(flow)
            except Exception as e:
                logger.warning("Flow export callback failed for %s: %s", flow.flow_id, e)