"""
Read events from JSONL file.
"""

from pathlib import Path
import json

def read_events(path):
    # Read JSONL file and return list of events
    p = Path(path)
    if not p.exists():
        return []
    events = []
    with open(p, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                events.append(json.loads(line))
            except:
                pass  # Skip bad lines
    return events
