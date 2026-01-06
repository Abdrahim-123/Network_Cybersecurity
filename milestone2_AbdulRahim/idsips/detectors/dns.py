"""
DNS detector - looks for suspicious DNS query names.
"""

from ..agent.logging import emit_event
import math

def calculate_entropy(s):
    # Calculate how random the string looks
    if not s:
        return 0.0

    # Count each character
    char_counts = {}
    for char in s:
        if char in char_counts:
            char_counts[char] += 1
        else:
            char_counts[char] = 1

    total_chars = len(s)
    entropy = 0.0
    for count in char_counts.values():
        prob = count / total_chars
        entropy -= prob * math.log2(prob)

    return entropy

def detect_dns(cfg, pkt, src, dst):
    # Check if this packet has DNS
    if not hasattr(pkt, "dns"):
        return

    dns = pkt.dns

    # Get the query name
    name = None
    if hasattr(dns, "qry_name"):
        name = dns.qry_name
    elif hasattr(dns, "qry_name_raw"):
        name = dns.qry_name_raw

    if not name:
        return

    name = str(name)

    # Get thresholds from config
    label_max = cfg["thresholds"]["dns_label_max"]
    name_max = cfg["thresholds"]["dns_name_max"]

    # Split name into labels
    labels = []
    for part in name.split("."):
        if part:  # skip empty parts
            labels.append(part)

    # Check for long labels
    long_label = False
    for label in labels:
        if len(label) > label_max:
            long_label = True
            break

    # Check if name is too long
    too_long = len(name) > name_max

    # Calculate entropy
    ent = calculate_entropy(name)
    entropy_threshold = 4.0
    high_entropy = ent >= entropy_threshold

    # If any check fails, emit event
    if long_label or too_long or high_entropy:
        emit_event(
            cfg,
            src=str(src) if src else "",
            dst=str(dst) if dst else "",
            proto="DNS",
            rule_id="DNS_SUSPICIOUS",
            severity="medium",
            summary="Suspicious DNS query name",
            metadata={
                "name": name,
                "long_label": long_label,
                "too_long": too_long,
                "entropy": round(ent, 2),
            },
        )
