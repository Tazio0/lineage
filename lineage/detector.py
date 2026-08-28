# detector.py
# Entry point for the Lineage detector.
# Responsibilities:
#   - Load and attach the eBPF probe (via BCC)
#   - Open the perf buffer
#   - Poll for kernel events in a loop
#   - Pass raw events to the engine for classification
