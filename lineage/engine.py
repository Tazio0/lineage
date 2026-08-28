# engine.py
# Core detection and classification logic.
# Responsibilities:
#   - Receive a structured process event (parent name, child name, PIDs, UID)
#   - Classify the parent against the baseline (allowlist / high-risk / unknown)
#   - Return an alert decision with a human-readable reason
#
# NOTE: This module must have NO dependency on BCC or the kernel.
# It only works with plain Python data so it can be unit tested independently.
