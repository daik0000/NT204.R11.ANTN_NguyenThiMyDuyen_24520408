import copy
import math
from pathlib import Path

import yaml

# src/utils/config.py -> parents[2] is the project root (independent of cwd)
PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_CONFIG_PATH = PROJECT_ROOT / "config" / "settings.yaml"

DEFAULT_CONFIG = {
    "decoder": {
        "enabled": True,
        "max_payload_bytes": 65536,
        "url_decode_passes": 1,
        "plus_as_space_in_query": True,
        "html_entity_content_types": ["text/html", "text/plain", "application/x-www-form-urlencoded"],
    },
    "preprocessor": {
        "unsupported_policy": "mark",
        "invalid_policy": "flag",
        "max_future_timestamp_skew_sec": 86400,
    },
    "flow": {
        "tcp_idle_timeout_sec": 300,
        "udp_idle_timeout_sec": 60,
        "tcp_handshake_timeout_sec": 30,
        "tcp_closed_linger_sec": 10,
        "tcp_close_requires_final_ack": False,
        "max_active_flows": 100000,
        "sweep_interval_sec": 1.0,
    },
}


def _merge_configs(default, user):
    """Recursively merge user into default; never mutate DEFAULT_CONFIG."""
    merged = copy.deepcopy(default)
    for key, value in user.items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = _merge_configs(merged[key], value)
        elif value is None and key in merged:
            continue  # section/value left empty in YAML -> keep default
        else:
            merged[key] = copy.deepcopy(value)
    return merged


def _is_number(v):
    return isinstance(v, (int, float)) and not isinstance(v, bool) and math.isfinite(v)


def _is_int(v):
    return isinstance(v, int) and not isinstance(v, bool)


def _check(cond, msg):
    if not cond:
        raise ValueError(f"Config error: {msg}")


def _check_unknown_keys(user):
    """Catch typos in key names within the 3 sections of Exercise 2."""
    for section, defaults in DEFAULT_CONFIG.items():
        sec = user.get(section) or {}
        _check(isinstance(sec, dict), f"'{section}' must be a mapping")
        for key in sec:
            _check(key in defaults, f"unknown key '{section}.{key}'")


def _validate(cfg):
    for name in DEFAULT_CONFIG:
        _check(isinstance(cfg.get(name), dict), f"'{name}' must be a mapping")

    dec, prep, flow = cfg["decoder"], cfg["preprocessor"], cfg["flow"]

    _check(isinstance(dec["enabled"], bool), "decoder.enabled must be true/false")
    _check(_is_int(dec["max_payload_bytes"]) and dec["max_payload_bytes"] > 0,
           "decoder.max_payload_bytes must be an integer > 0")
    _check(_is_int(dec["url_decode_passes"]) and dec["url_decode_passes"] >= 1,
           "decoder.url_decode_passes must be an integer >= 1")
    _check(isinstance(dec["plus_as_space_in_query"], bool),
           "decoder.plus_as_space_in_query must be true/false")
    _check(isinstance(dec["html_entity_content_types"], list),
           "decoder.html_entity_content_types must be a list")

    _check(prep["unsupported_policy"] in ("mark", "skip"),
           "preprocessor.unsupported_policy must be 'mark' or 'skip'")
    _check(prep["invalid_policy"] in ("flag", "drop"),
           "preprocessor.invalid_policy must be 'flag' or 'drop'")
    _check(_is_number(prep["max_future_timestamp_skew_sec"]) and prep["max_future_timestamp_skew_sec"] >= 0,
           "preprocessor.max_future_timestamp_skew_sec must be a number >= 0")

    for key in ("tcp_idle_timeout_sec", "udp_idle_timeout_sec",
                "tcp_handshake_timeout_sec", "tcp_closed_linger_sec"):
        _check(_is_number(flow[key]) and flow[key] > 0, f"flow.{key} must be a number > 0")
    _check(isinstance(flow["tcp_close_requires_final_ack"], bool),
           "flow.tcp_close_requires_final_ack must be true/false")
    _check(_is_int(flow["max_active_flows"]) and flow["max_active_flows"] >= 1,
           "flow.max_active_flows must be an integer >= 1")
    _check(_is_number(flow["sweep_interval_sec"]) and flow["sweep_interval_sec"] >= 0,
           "flow.sweep_interval_sec must be a number >= 0")


def load_config(path=None):
    """
    Load YAML, merge with defaults, then validate.
    - path=None: use config/settings.yaml at the project root; if missing, use defaults.
    - path explicitly provided: the file must exist, otherwise raise FileNotFoundError.
    """
    explicit = path is not None
    target = Path(path) if explicit else DEFAULT_CONFIG_PATH

    user_config = {}
    if target.exists():
        try:
            with open(target, "r", encoding="utf-8") as f:
                user_config = yaml.safe_load(f) or {}
        except yaml.YAMLError as e:
            raise ValueError(f"Config error: cannot parse {target}: {e}") from e
        _check(isinstance(user_config, dict), f"{target} must contain a YAML mapping at top level")
    elif explicit:
        raise FileNotFoundError(f"Config file not found: {target}")

    _check_unknown_keys(user_config)
    final_config = _merge_configs(DEFAULT_CONFIG, user_config)
    _validate(final_config)
    return final_config