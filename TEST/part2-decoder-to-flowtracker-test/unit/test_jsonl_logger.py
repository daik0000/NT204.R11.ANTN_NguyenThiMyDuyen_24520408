import json
import pytest

from src.logging.jsonl_logger import JSONLLogger
from src.models.event import IDSEvent
from src.models.flow import Flow

def test_logger_writes_both_event_and_flow(tmp_path):
    """Test 1: JSONLLogger can write both IDSEvent and Flow seamlessly."""
    log_file = tmp_path / "output.jsonl"
    
    # Create valid dummy instances
    event = IDSEvent(packet_id=1, timestamp=1600000000.0)
    flow = Flow(
        flow_id="f1", protocol="TCP",
        endpoint_a={"ip": "10.0.0.1", "port": 1234},
        endpoint_b={"ip": "10.0.0.2", "port": 80},
        start_time=1.0, last_seen=2.0,
        state="ESTABLISHED"
    )
    
    # Write using Context Manager
    with JSONLLogger(str(log_file)) as logger:
        logger.log(event)
        logger.log(flow)
        
    lines = log_file.read_text(encoding="utf-8").strip().split("\n")
    assert len(lines) == 2
    
    data_event = json.loads(lines[0])
    data_flow = json.loads(lines[1])
    
    assert data_event["packet_id"] == 1
    assert data_flow["flow_id"] == "f1"
    # Ensure properties not backed by fields (like Flow.duration) are included
    assert "duration" in data_flow 
    assert data_flow["duration"] == 1.0


def test_logger_never_leaks_payload(tmp_path):
    """Test 2: Ensure raw bytes payload is excluded from JSON output."""
    log_file = tmp_path / "output_payload.jsonl"
    
    event = IDSEvent(
        packet_id=2, 
        timestamp=0.0, 
        payload=b"CONFIDENTIAL_BYTES"
    )
    
    with JSONLLogger(str(log_file)) as logger:
        logger.log(event)
        
    data = json.loads(log_file.read_text(encoding="utf-8").strip())
    assert "payload" not in data


def test_logger_survives_missing_to_dict(tmp_path, capsys):
    """Test 3: Logger catches exception on bad records and continues running."""
    log_file = tmp_path / "output_err.jsonl"
    
    class BadRecord:
        pass # Object without a to_dict() method
        
    with JSONLLogger(str(log_file)) as logger:
        logger.log(BadRecord())
        
    # Read stdout to confirm the error was gracefully caught and printed
    captured = capsys.readouterr()
    assert "[ERROR]" in captured.out or "[ERROR]" in captured.err
    
    # File should remain empty without crashing the test runner
    assert log_file.read_text(encoding="utf-8") == ""


def test_logger_preserves_unicode(tmp_path):
    """Test 4: ensure_ascii=False correctly keeps Unicode characters readable."""
    log_file = tmp_path / "output_unicode.jsonl"
    
    event = IDSEvent(packet_id=3, timestamp=0.0)
    event.app_fields = {"message": "Xin chào thế giới 🌍"}
    
    with JSONLLogger(str(log_file)) as logger:
        logger.log(event)
        
    raw_text = log_file.read_text(encoding="utf-8").strip()
    
    # Assert the raw file contains the actual characters, not escaped unicode (\u...)
    assert "Xin chào thế giới 🌍" in raw_text
    assert "\\u" not in raw_text