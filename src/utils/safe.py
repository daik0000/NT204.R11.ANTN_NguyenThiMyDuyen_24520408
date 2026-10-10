import logging
from functools import wraps
from typing import Callable, Any, Dict

# Initialize module-level logger
logger = logging.getLogger(__name__)

def safe_parse(func: Callable[..., Dict[str, Any]]) -> Callable[..., Dict[str, Any]]:
    """
    A decorator that wraps packet parser functions to provide global error handling.
    Catches all parsing exceptions (e.g., truncated payloads, malformed headers) 
    and prevents them from propagating up and crashing the main capture pipeline.
    
    Returns a fallback dictionary with status="MALFORMED" upon failure.
    """
    @wraps(func)
    def wrapper(*args, **kwargs) -> Dict[str, Any]:
        try:
            # Attempt to execute the actual parser function
            return func(*args, **kwargs)
        except Exception as e:
            # Catch broad exceptions because malformed packets can trigger unpredictable 
            # errors in parsing libraries (e.g., struct.error, IndexError, ValueError).
            logger.debug("Malformed packet caught in parser '%s': %s", func.__name__, e)
            
            # Return a safe fallback instead of crashing
            return {
                "status": "MALFORMED",
                "error_info": {
                    "layer": func.__name__,
                    "detail": str(e),
                },
            }
    return wrapper

def safe_stage(stage_name: str, event_index: int = 0) -> Callable:
    """
    A decorator for Part 2 pipeline stages (Decoder, Preprocessor, Flow Tracker).
    Catches standard exceptions to ensure the pipeline survives anomalous events.
    Records error_info ONLY if it is currently None, preserving prior parser errors.
    Always returns the event so the next stage can proceed with default/partial fields.

    Args:
        stage_name: Value stored in error_info["layer"] when the stage fails.
        event_index: Position of the event among the positional arguments.
            Use 0 for plain functions, 1 for methods (index 0 is `self`),
            e.g. @safe_stage("flow_tracker", event_index=1) on FlowTracker.update().
    """
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            try:
                # Attempt to execute the pipeline stage on the event
                return func(*args, **kwargs)
            except Exception as e: # Explicitly Exception, not BaseException (allows KeyboardInterrupt)
                # A stage failure is unexpected (unlike a malformed packet), so keep it visible
                logger.warning("Exception caught in stage '%s' (%s): %s", stage_name, func.__name__, e)
                
                # The event may be passed positionally or as the keyword "event"
                event = args[event_index] if len(args) > event_index else kwargs.get("event")
                
                # Only record error if no previous stage (like Parser) has set it.
                # Guarded because the argument may not be a writable event (e.g. None):
                # the error handler itself must never raise.
                try:
                    if getattr(event, "error_info", None) is None:
                        event.error_info = {
                            "layer": stage_name,
                            "detail": str(e),
                        }
                except Exception:
                    pass
                
                # Return the event (potentially partially modified) to continue the pipeline
                return event
        return wrapper
    return decorator

if __name__ == "__main__":
    import logging
    from dataclasses import dataclass
    
    # Set up basic logging configuration for testing purposes
    logging.basicConfig(level=logging.DEBUG, format="%(levelname)s - %(message)s")

    # --- PART 1 TESTS ---
    @safe_parse
    def dummy_success_parser(packet):
        return {"status": "OK", "layer": "IPv4", "src_ip": "192.168.1.1"}

    @safe_parse
    def dummy_fail_parser(packet):
        return {"status": "OK", "layer": "IPv4", "src_ip": packet["ip_address"]}

    print("--- TEST 1: PARSER RUNNING NORMALLY ---")
    result_ok = dummy_success_parser({"some_data": "ok"})
    print(f"Result: {result_ok}\n")

    print("--- TEST 2: PARSER CRASH ---")
    result_bad = dummy_fail_parser({"some_data": "bad"})
    print(f"Result: {result_bad}\n")

    # --- PART 2 TESTS ---
    @dataclass
    class DummyEvent:
        error_info: Dict[str, Any] | None = None

    @safe_stage("DecoderStage")
    def dummy_crashing_stage(event):
        raise ValueError("Unexpected decoding error")

    print("--- TEST 3: STAGE CRASH (No prior error) ---")
    ev1 = DummyEvent()
    result_ev1 = dummy_crashing_stage(ev1)
    print(f"Result: {result_ev1}\n")

    print("--- TEST 4: STAGE CRASH (Prior parser error preserved) ---")
    ev2 = DummyEvent(error_info={"layer": "IPv4", "detail": "Truncated header"})
    result_ev2 = dummy_crashing_stage(ev2)
    print(f"Result: {result_ev2}")