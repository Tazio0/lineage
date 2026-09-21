# detector.py
# Entry point for the Lineage detector.
# Loads the eBPF probe via BCC, polls for kernel events,
# and passes them through the classification engine.

import os
import sys

try:
    from bcc import BPF
except ImportError:
    BPF = None

from lineage.alerts import format_alert
from lineage.engine import classify_event

PROBE_PATH = os.path.join(os.path.dirname(__file__), "..", "probes", "exec_probe.c")


def process_event(comm: bytes | str, filename: bytes | str, uid: int) -> str | None:
    """Process a raw event from the probe and return an alert string if suspicious."""
    if isinstance(comm, bytes):
        parent = comm.decode("utf-8", errors="replace").rstrip("\x00")
    else:
        parent = comm

    if isinstance(filename, bytes):
        child_path = filename.decode("utf-8", errors="replace").rstrip("\x00")
    else:
        child_path = filename

    child = os.path.basename(child_path)

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


def handle_event(cpu, data, size, bpf_instance):
    """Callback invoked by BCC for each perf buffer event."""
    event = bpf_instance["events"].event(data)
    alert = process_event(event.comm, event.filename, event.uid)
    if alert:
        print(alert)


def main():
    if BPF is None:
        print(
            "error: bcc python package is required to run the detector",
            file=sys.stderr,
        )
        sys.exit(1)

    if os.geteuid() != 0:
        print("error: lineage requires root (BCC needs kernel access)", file=sys.stderr)
        sys.exit(1)

    with open(PROBE_PATH, "r") as f:
        probe_source = f.read()

    bpf_instance = BPF(text=probe_source)

    bpf_instance["events"].open_perf_buffer(
        lambda cpu, data, size: handle_event(cpu, data, size, bpf_instance)
    )

    print("lineage: watching for suspicious process spawning... (ctrl-c to stop)")

    try:
        while True:
            bpf_instance.perf_buffer_poll()
    except KeyboardInterrupt:
        print("\nlineage: stopped")


if __name__ == "__main__":
    main()
