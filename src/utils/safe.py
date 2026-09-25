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

if __name__ == "__main__":
    import logging
    
    # Set up basic logging configuration for testing purposes
    logging.basicConfig(level=logging.DEBUG, format="%(levelname)s - %(message)s")

    # 1. Simulates normal operation
    @safe_parse
    def dummy_success_parser(packet):
        return {"status": "OK", "layer": "IPv4", "src_ip": "192.168.1.1"}

    # 2. Simulates a parser that fails due to a malformed packet (missing key) or bad code
    @safe_parse
    def dummy_fail_parser(packet):
        return {"status": "OK", "layer": "IPv4", "src_ip": packet["ip_address"]}

    print("--- TEST 1: PARSER RUNNING NORMALLY ---")
    result_ok = dummy_success_parser({"some_data": "ok"})
    print(f"Result: {result_ok}\n")

    print("--- TEST 2: PARSER CRASH ---")
    result_bad = dummy_fail_parser({"some_data": "bad"})
    print(f"Result: {result_bad}")