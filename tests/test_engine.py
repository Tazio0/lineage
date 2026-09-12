# tests/test_engine.py
# Unit tests for the detection and classification engine (lineage/engine.py).

from lineage.engine import classify_event


def test_legitimate_spawner_returns_no_alert():
    """a known-safe parent like gnome-terminal spawning bash should  not alert"""
    result = classify_event(parent="gnome-terminal", child="bash")
    assert result["level"] == "NONE"


def test_high_risk_service_spawning_shell_returns_critical():
    """A high-risk service like nginx spawning a shell should be CRITICAL"""
    result = classify_event(parent="nginx", child="sh")
    assert result["level"] == "CRITICAL"


def test_unknown_parent_spawning_shell_returns_warning():
    """An unrecognised parent like evince spawning a shell should be a WARNING"""
    result = classify_event(parent="evince", child="sh")
    assert result["level"] == "WARNING"


def test_non_shell_child_always_returns_no_alert():
    """Even a high-risk parent spawning a non-shell child is fine."""
    result = classify_event(parent="nginx", child="worker")
    assert result["level"] == "NONE"
