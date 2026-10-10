from typing import Any
from src.utils.safe import safe_stage
from src.preprocessor.validator import validate
from src.preprocessor.normalizer import normalize
from src.preprocessor.defaults import fill_defaults, apply_policies

@safe_stage("preprocessor")
def preprocess_event(event: Any, cfg: Any) -> Any:
    """
    The orchestrator for the Preprocessor pipeline.
    Runs validation, conditional normalization, default filling, and policy enforcement.
    Never raises exceptions, ensuring resilience against malformed or empty events.
    """
    # Fail-safe default: if any step below raises, safe_stage returns the event as-is,
    # so it must already carry a conservative verdict instead of None/None.
    event.preprocess_status = "invalid"
    event.processing_action = "flagged"
    
    # 0. Initialize reason tracking early to allow all stages to append safely
    if not isinstance(getattr(event, "reason", None), list):
        event.reason = []
        
    # 1. Validate (Check constraints, missing required fields, and supported protocols)
    status, val_reasons = validate(event, cfg)
    
    # Merge validation reasons into event.reason without duplicates
    for r in val_reasons:
        if r not in event.reason:
            event.reason.append(r)
            
    # 2. Normalize (Format IPs, domains, URIs, timestamps)
    # CRITICAL: We skip normalization if the event is already "invalid" (e.g., malformed, 
    # out-of-bounds ports) to prevent silently "fixing" or obscuring garbage data.
    has_normalizations = False
    if status != "invalid":
        changes = normalize(event, cfg)
        has_normalizations = len(changes) > 0
            
    # 3. Fill Defaults (Guarantees safe schema/types for downstream modules like FlowTracker)
    has_defaults = fill_defaults(event)
    
    # 4. Apply Policies (Determines final preprocess_status and processing_action)
    # We pass the full merged event.reason so policies can evaluate all flags (e.g., unsupported_network)
    apply_policies(event, status, event.reason, cfg, has_normalizations, has_defaults)
    
    return event