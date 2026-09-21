# tests/test_detector.py
# Unit tests for the detector event processing logic (lineage/detector.py).

from lineage.detector import process_event


def test_process_event_critical_on_high_risk_service_spawning_shell():
    """Event with high-risk parent spawning shell yields a CRITICAL alert."""
    alert = process_event(comm=b"nginx\x00\x00", filename=b"/bin/sh\x00", uid=33)
    assert alert is not None
    assert "CRITICAL" in alert
    assert "nginx" in alert
    assert "sh" in alert
    assert "33" in alert
    assert "T1059" in alert


def test_process_event_none_on_legitimate_terminal():
    """Event with legitimate terminal spawning shell should yield None (no alert)."""
    alert = process_event(
        comm=b"gnome-terminal\x00", filename=b"/usr/bin/bash\x00", uid=1000
    )
    assert alert is None


def test_process_event_warning_on_unknown_parent():
    """Event with unknown parent spawning shell should yield a WARNING alert string."""
    alert = process_event(comm=b"evince\x00", filename=b"/bin/bash\x00", uid=1000)
    assert alert is not None
    assert "WARNING" in alert
    assert "evince" in alert


def test_process_event_none_on_non_shell():
    """Event spawning a non-shell binary should yield None."""
    alert = process_event(comm=b"nginx\x00", filename=b"/usr/sbin/worker\x00", uid=33)
    assert alert is None
