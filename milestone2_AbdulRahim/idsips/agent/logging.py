"""
Logging helpers for writing JSONL logs.
"""

from pathlib import Path
import datetime
import json

def logs_dir(cfg):
    # Get the logs directory from config
    p = Path(cfg["paths"]["logs_dir"]).resolve()
    # Create it if it doesn't exist
    if not p.exists():
        p.mkdir(parents=True)
    return p

def now_iso():
    # Get current time in ISO format
    return datetime.datetime.now(datetime.timezone.utc).isoformat()

def write_jsonl(path, obj):
    # Write a dict as JSON line to file
    with open(path, "a", encoding="utf-8") as f:
        json_str = json.dumps(obj, ensure_ascii=False, separators=(',', ':'))
        f.write(json_str + "\n")

def emit_event(cfg, **kwargs):
    # Emit a detection event
    base = {"ts": now_iso(), "schema_version": "1.0"}
    # Merge base with kwargs
    event = base.copy()
    event.update(kwargs)
    write_jsonl(logs_dir(cfg) / "detections.jsonl", event)

def emit_ops(cfg, level, component, msg, kv=None):
    # Emit an operational event
    if kv is None:
        kv = {}
    obj = {"ts": now_iso(), "level": level, "component": component, "msg": msg, "kv": kv}
    write_jsonl(logs_dir(cfg) / "ops.jsonl", obj)
