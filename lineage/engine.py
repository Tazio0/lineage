# engine.py
# Core detection and classification logic.
# Responsibilities:
#   - Receive a structured process event (parent name, child name, PIDs, UID)
#   - Classify the parent against the baseline (allowlist / high-risk / unknown)
#   - Return an alert decision with a human-readable reason
#
# NOTE: This module must have NO dependency on BCC or the kernel.
# It only works with plain Python data so it can be unit tested independently.

import os

SHELLS = {"sh", "bash", "dash", "zsh", "fish", "csh", "ksh"}

HIGH_RISK_PARENTS = {"nginx", "apache2", "httpd", "postgres", "mysqld", "sshd"}

LEGITIMATE_PARENTS = {
    "gnome-terminal",
    "konsole",
    "xterm",
    "alacritty",
    "kitty",
    "bash",
    "zsh",
    "fish",
    "tmux",
    "screen",
}


def classify_event(parent: str, child: str) -> dict:
    """Classify a process spawning event and return an alert decision."""
    parent_name = parent.strip()
    child_name = os.path.basename(child.strip())

    if child_name not in SHELLS:
        return {"level": "NONE", "reason": f"{child_name} is not a shell"}

    if parent_name in HIGH_RISK_PARENTS:
        return {
            "level": "CRITICAL",
            "reason": f"{parent_name} is a high-risk service and spawned {child_name}",
        }

    if parent_name in LEGITIMATE_PARENTS:
        return {
            "level": "NONE",
            "reason": f"{parent_name} spawning {child_name} is expected",
        }

    return {
        "level": "WARNING",
        "reason": f"{parent_name} is not recognised and spawned {child_name}",
    }
