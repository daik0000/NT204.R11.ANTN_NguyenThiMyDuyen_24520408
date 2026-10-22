import pytest
import yaml

from src.utils.config import DEFAULT_CONFIG, load_config


def _load(tmp_path, data):
    path = tmp_path / "settings.yaml"
    path.write_text(yaml.safe_dump(data), encoding="utf-8")
    return load_config(path)


def test_missing_engine_section_uses_defaults(tmp_path):
    cfg = _load(tmp_path, {"flow": {"tcp_idle_timeout_sec": 100}})
    assert cfg["engine"] == DEFAULT_CONFIG["engine"]
    assert cfg["flow"]["tcp_idle_timeout_sec"] == 100


def test_project_settings_has_engine_section():
    cfg = load_config()
    assert cfg["engine"]["enabled"] is True
    assert cfg["engine"]["rule_files"] == [{"path": "config/rules/local.rules", "enabled": True}]
    assert cfg["engine"]["disabled_sids"] == []
    assert cfg["engine"]["default_priority"] == 3


def test_partial_engine_section_keeps_other_defaults(tmp_path):
    cfg = _load(tmp_path, {"engine": {"enabled": False}})
    assert cfg["engine"]["enabled"] is False
    assert cfg["engine"]["default_priority"] == 3


def test_rule_file_enabled_defaults_to_true(tmp_path):
    cfg = _load(tmp_path, {"engine": {"rule_files": [{"path": "a.rules"}]}})
    assert cfg["engine"]["rule_files"] == [{"path": "a.rules", "enabled": True}]


def test_empty_engine_section_uses_defaults(tmp_path):
    path = tmp_path / "settings.yaml"
    path.write_text("engine:\n", encoding="utf-8")
    assert load_config(path)["engine"] == DEFAULT_CONFIG["engine"]


def test_default_config_not_mutated(tmp_path):
    _load(tmp_path, {"engine": {"rule_files": [{"path": "a.rules"}]}})
    assert DEFAULT_CONFIG["engine"]["rule_files"] == [{"path": "config/rules/local.rules", "enabled": True}]


@pytest.mark.parametrize("engine, fragment", [
    ({"enabled": "yes"}, "engine.enabled"),
    ({"enabled": 1}, "engine.enabled"),
    ({"rule_files": "a.rules"}, "engine.rule_files must be a list"),
    ({"rule_files": ["a.rules"]}, "engine.rule_files[0]"),
    ({"rule_files": [{"enabled": True}]}, "engine.rule_files[0].path"),
    ({"rule_files": [{"path": 5}]}, "engine.rule_files[0].path"),
    ({"rule_files": [{"path": ""}]}, "engine.rule_files[0].path"),
    ({"rule_files": [{"path": "a.rules", "enabled": "true"}]}, "engine.rule_files[0].enabled"),
    ({"rule_files": [{"path": "a.rules", "extra": 1}]}, "unknown key"),
    ({"disabled_sids": 1000001}, "engine.disabled_sids"),
    ({"disabled_sids": [1000001, "1000002"]}, "engine.disabled_sids"),
    ({"disabled_sids": [True]}, "engine.disabled_sids"),
    ({"disabled_sids": [1.5]}, "engine.disabled_sids"),
    ({"default_priority": 0}, "engine.default_priority"),
    ({"default_priority": "3"}, "engine.default_priority"),
    ({"default_priority": 2.5}, "engine.default_priority"),
    ({"default_priority": True}, "engine.default_priority"),
    ({"unknown_key": 1}, "unknown key 'engine.unknown_key'"),
])
def test_invalid_engine_config_raises(tmp_path, engine, fragment):
    with pytest.raises(ValueError, match="Config error") as exc:
        _load(tmp_path, {"engine": engine})
    assert fragment in str(exc.value)


def test_engine_must_be_mapping(tmp_path):
    with pytest.raises(ValueError, match="engine"):
        _load(tmp_path, {"engine": [1, 2]})
