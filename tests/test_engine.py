# tests/test_engine.py
# Unit tests for the detection and classification engine (lineage/engine.py).
#
# Test cases to implement:
#   - Legitimate spawner (e.g. gnome-terminal -> bash) should return NO alert
#   - High-risk service spawning shell (e.g. nginx -> /bin/sh) should return CRITICAL alert
#   - Unknown parent spawning shell (e.g. evince -> /bin/sh) should return WARNING alert
#   - Non-shell child process should always return NO alert regardless of parent
