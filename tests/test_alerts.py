# tests/test_alerts.py
# Unit tests for alert formatting (lineage/alerts.py).

from lineage.alerts import format_alert


def test_critical_alert_contains_required_fields():
    """A CRITICAL alert must include all key fields for an analyst to act on."""
    event = {
        "level": "CRITICAL",
        "reason": "nginx is a high-risk service and spawned sh",
        "parent": "nginx",
        "child": "sh",
        "uid": 33,
    }
    output = format_alert(event)
    assert "CRITICAL" in output
    assert "nginx" in output
    assert "sh" in output
    assert "33" in output
    assert "T1059" in output  # MITRE ATT&CK technique for command interpreter
    assert "nginx is a high-risk service and spawned sh" in output


def test_warning_alert_contains_required_fields():
    """A WARNING alert must also include all key fields."""
    event = {
        "level": "WARNING",
        "reason": "evince is not recognised and spawned sh",
        "parent": "evince",
        "child": "sh",
        "uid": 1000,
    }
    output = format_alert(event)
    assert "WARNING" in output
    assert "evince" in output
    assert "sh" in output
    assert "1000" in output
    assert "T1059" in output
    assert "evince is not recognised and spawned sh" in output


def test_alert_output_is_human_readable():
    """Alert must not contain raw byte strings or null padding."""
    event = {
        "level": "CRITICAL",
        "reason": "nginx is a high-risk service and spawned sh",
        "parent": "nginx",
        "child": "sh",
        "uid": 33,
    }
    output = format_alert(event)
    assert "b'" not in output
    assert "\\x00" not in output
    assert isinstance(output, str)
