from datetime import datetime, timezone

MITRE_TAG = "T1059"  # Command and Scripting Interpreter


def format_alert(event: dict) -> str:
    """Format a classification result into a human-readable alert string."""
    timestamp = datetime.now(timezone.utc).isoformat()
    level = event["level"]
    parent = event["parent"]
    child = event["child"]
    uid = event["uid"]
    reason = event["reason"]

    return (
        f"[{timestamp}] {level}: "
        f"parent={parent} child={child} uid={uid} "
        f"mitre={MITRE_TAG} — {reason}"
    )
