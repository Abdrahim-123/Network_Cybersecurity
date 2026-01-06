"""
Utility functions.
"""

from pathlib import Path
import datetime
import json

def logs_dir(cfg):
    # Get logs directory
    p = Path(cfg["paths"]["logs_dir"]).resolve()
    if not p.exists():
        p.mkdir(parents=True)
    return p

def now_iso():
    # Current time in ISO
    return datetime.datetime.now(datetime.timezone.utc).isoformat()

def json_dumps(obj):
    # Dump to JSON string
    try:
        import orjson
        return orjson.dumps(obj).decode("utf-8")
    except:
        return json.dumps(obj, ensure_ascii=False)
