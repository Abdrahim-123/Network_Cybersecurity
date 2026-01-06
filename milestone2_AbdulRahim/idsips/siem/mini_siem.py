import argparse, sys, yaml, collections, time
from .ingest import read_events
from .alerts import emit_alert

def load_cfg(path="config.yaml"):
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)

def timeline_view(events):
    # Group events by time
    buckets = {}
    for e in events:
        ts = e.get("ts", "")[:16]
        if ts not in buckets:
            buckets[ts] = 0
        buckets[ts] += 1
    for k in sorted(buckets.keys()):
        print(k, buckets[k])

def top_talkers(events):
    # Count sources
    c = collections.Counter()
    for e in events:
        src = e.get("src", "")
        c[src] += 1
    for ip, n in c.most_common(10):
        print(f"{ip:>16}  {n}")

def rule_stats(events):
    # Count rule IDs
    c = collections.Counter()
    for e in events:
        rule = e.get("rule_id", "")
        c[rule] += 1
    for r, n in c.most_common():
        print(f"{r:>16}  {n}")

def correlate(cfg, events):
    # Look for correlations
    window = 60.0
    by_src = {}
    by_rule = {}

    from datetime import datetime

    def to_epoch(ts):
        try:
            return datetime.fromisoformat(ts).timestamp()
        except:
            return time.time()

    for e in events:
        t = to_epoch(e.get("ts", ""))
        src = e.get("src", "")
        rule = e.get("rule_id", "")

        if src not in by_src:
            by_src[src] = []
        by_src[src].append(t)

        if rule not in by_rule:
            by_rule[rule] = []
        by_rule[rule].append(t)

    for src, times in by_src.items():
        times.sort()
        i = 0
        for j in range(len(times)):
            while times[j] - times[i] > window:
                i += 1
            if (j - i + 1) >= 30:
                emit_alert(cfg, "ALERT_ICMP_FLOOD", "high",
                           "High volume events from " + src + " in 60s",
                           {"src": src}, j - i + 1)
                break

    for r, times in by_rule.items():
        if len(times) >= 50:
            emit_alert(cfg, "ALERT_REPEATED_RULE", "medium",
                       "Rule " + r + " fired " + str(len(times)) + " times",
                       {"rule_id": r}, len(times))

def main(argv=None):
    p = argparse.ArgumentParser(prog="mini-siem")
    p.add_argument("--config", default="config.yaml")
    p.add_argument("--timeline", action="store_true")
    p.add_argument("--top", action="store_true")
    p.add_argument("--rule-stats", action="store_true")
    args = p.parse_args(argv)
    cfg = load_cfg(args.config)
    events = read_events("./logs/detections.jsonl")
    print(f"Mini-SIEM: Loaded {len(events)} detection events")
    if args.timeline:
        print("Timeline View:")
        timeline_view(events)
    if args.top:
        print("Top Talkers:")
        top_talkers(events)
    if args.rule_stats:
        print("Rule Statistics:")
        rule_stats(events)
    correlate(cfg, events)
    print("Mini-SIEM analysis completed successfully.")
    return 0

if __name__ == "__main__":
    sys.exit(main())
