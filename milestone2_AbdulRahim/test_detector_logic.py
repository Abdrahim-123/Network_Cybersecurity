#!/usr/bin/env python3
"""Debug script to trace DNS detector logic"""
import pyshark
import asyncio
import yaml

# Load config
with open('config.yaml', 'r') as f:
    cfg = yaml.safe_load(f)

print("Config thresholds:")
print(f"  dns_label_max: {cfg['thresholds']['dns_label_max']}")
print(f"  dns_name_max: {cfg['thresholds']['dns_name_max']}")
print(f"  dns_suspicious rule enabled: {cfg['rules']['dns_suspicious']}")
print()

loop = asyncio.new_event_loop()
asyncio.set_event_loop(loop)

cap = pyshark.FileCapture(
    r'c:\Users\mmr96\Desktop\Course Project\pcaps\dns_examples.pcapng',
    keep_packets=False
)

import math
def _entropy(s: str) -> float:
    if not s:
        return 0.0
    from collections import Counter
    n = len(s)
    c = Counter(s)
    return -sum((cnt/n) * math.log2(cnt/n) for cnt in c.values())

for pkt in cap:
    if hasattr(pkt, 'dns'):
        dns = pkt.dns
        name = getattr(dns, 'qry_name', None) or getattr(dns, 'qry_name_raw', None)
        if name:
            name = str(name)
            labels = [l for l in name.split(".") if l]
            long_label = any(len(l) > cfg['thresholds']['dns_label_max'] for l in labels)
            too_long = len(name) > cfg['thresholds']['dns_name_max']
            ent = _entropy(name)
            high_entropy = ent >= 4.0
            
            print(f"DNS: {name}")
            print(f"  Labels: {labels}")
            print(f"  Max label len: {max(len(l) for l in labels) if labels else 0}")
            print(f"  Total len: {len(name)}")
            print(f"  Entropy: {ent:.2f}")
            print(f"  long_label={long_label}, too_long={too_long}, high_entropy={high_entropy}")
            print(f"  -> Suspicious: {long_label or too_long or high_entropy}")
            print()

cap.close()
