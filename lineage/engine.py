# engine.py
# Core detection and classification logic.
# Responsibilities:
#   - Receive a structured process event (parent name, child name, PIDs, UID)
#   - Classify the parent against the baseline (allowlist / high-risk / unknown)
#   - Return an alert decision with a human-readable reason
#
# NOTE: This module must have NO dependency on BCC or the kernel.
# It only works with plain Python data so it can be unit tested independently.

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
    if child not in SHELLS:
        return {"level": "NONE", "reason": f"{child} is not a shell"}

    if parent in HIGH_RISK_PARENTS:
        return {
            "level": "CRITICAL",
            "reason": f"{parent} is a high-risk service and spawned {child}",
        }

    if parent in LEGITIMATE_PARENTS:
        return {"level": "NONE", "reason": f"{parent} spawning {child} is expected"}

    return {
        "level": "WARNING",
        "reason": f"{parent} is not recognised and spawned {child}",
    }
