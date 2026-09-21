# tests/test_scenarios.py
# Acceptance tests: simulate real attack and benign scenarios
# through the full Python detection pipeline (engine + alerts).

from lineage.alerts import format_alert
from lineage.engine import classify_event


def _simulate_event(parent, child, uid=1000):
    """Run an event through the full pipeline: classify then format."""
    result = classify_event(parent=parent, child=child)
    if result["level"] == "NONE":
        return None
    alert_event = {
        "level": result["level"],
        "reason": result["reason"],
        "parent": parent,
        "child": child,
        "uid": uid,
    }
    return format_alert(alert_event)


def test_scenario_web_shell_exploitation():
    """Scenario 1: nginx spawning /bin/sh must produce a CRITICAL alert."""
    output = _simulate_event(parent="nginx", child="sh", uid=33)
    assert output is not None
    assert "CRITICAL" in output
    assert "nginx" in output
    assert "T1059" in output


def test_scenario_legitimate_terminal_use():
    """Scenario 2: gnome-terminal spawning bash must produce no alert."""
    output = _simulate_event(parent="gnome-terminal", child="bash")
    assert output is None


def test_scenario_unknown_process_spawning_shell():
    """Scenario 3: evince spawning bash must produce a WARNING alert."""
    output = _simulate_event(parent="evince", child="bash", uid=1000)
    assert output is not None
    assert "WARNING" in output
    assert "evince" in output
