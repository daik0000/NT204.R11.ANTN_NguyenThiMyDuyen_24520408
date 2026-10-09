import html
from typing import Dict, Any

def _unescape(text: str) -> str:
    """html.unescape only when an '&' is present (cheap pre-check)."""
    return html.unescape(text) if '&' in text else text

def apply_html_decoding(decoded_obj: Dict[str, Any]) -> Dict[str, Any]:
    """
    Applies HTML entity decoding to a previously decoded field object.
    Supports both scalar strings (e.g., HTTP body) and lists of key-value tuples (e.g., form/query params).
    Returns a NEW dict; the object passed in is never modified.
    
    Notes:
    - This must run AFTER percent-decoding and charset-decoding.
    - html.unescape operates safely without raising exceptions.
    - It supports HTML5 specifications, meaning it successfully decodes entities 
      even without a trailing semicolon in certain contexts (e.g., '&amp' -> '&').
    - Entities are decoded ONCE: an object already marked with "html_entity" is returned unchanged.
    - Do NOT apply this to a whole URI or query string: the legacy semicolon-less entities would
      corrupt it ("/s?a=1&region=eu" -> "/s?a=1\u00aeion=eu"). Apply it only to individual
      parameter values/keys (after splitting on '&') and to text bodies.
    """
    # Do not process missing values or explicitly skipped binary content
    if "value" not in decoded_obj or decoded_obj.get("status") == "SKIPPED":
        return decoded_obj
    
    # Already decoded once: decoding again would turn "&amp;lt;" into "<" instead of "&lt;"
    if "html_entity" in decoded_obj.get("encodings", []):
        return decoded_obj

    value = decoded_obj["value"]
    new_value = value
    changed = False

    if isinstance(value, str):
        new_value = _unescape(value)
        changed = new_value != value
                
    elif isinstance(value, list):
        # Process list of (key, value) pairs for query strings and form parameters
        new_list = []
        for item in value:
            if isinstance(item, (tuple, list)) and len(item) == 2:
                k, v = item
                new_k = _unescape(k) if isinstance(k, str) else k
                new_v = _unescape(v) if isinstance(v, str) else v
                if new_k != k or new_v != v:
                    changed = True
                new_list.append(type(item)((new_k, new_v)))
            else:
                # Not a key/value pair: keep it untouched instead of crashing the whole stage
                new_list.append(item)
        new_value = new_list

    if not changed:
        return decoded_obj

    result = dict(decoded_obj)
    result["value"] = new_value
    
    # Append "html_entity" to the encodings tracker (on a copy, never on the caller's list)
    result["encodings"] = list(decoded_obj.get("encodings", [])) + ["html_entity"]

    return result