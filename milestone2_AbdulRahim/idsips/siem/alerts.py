"""
Emit alerts to logs and console.
"""

from ..agent.utils import logs_dir, now_iso, json_dumps

def emit_alert(cfg, alert_id, severity, summary, entities, evidence_count):
    # Create alert object
    obj = {
        "ts": now_iso(),
        "alert_id": alert_id,
        "severity": severity,
        "summary": summary,
        "entities": entities,
        "evidence_count": int(evidence_count),
    }
    # Write to alerts file
    p = logs_dir(cfg) / "alerts.jsonl"
    with open(p, "a", encoding="utf-8") as f:
        f.write(json_dumps(obj) + "\n")
    # Print to console
    print("[" + severity + "] " + alert_id + ": " + summary)
