"""
ICMP detector - looks for ICMP flood by counting packets per second from one source.
"""

from ..agent.logging import emit_event
import time

# Global list to store ICMP packets: (timestamp, source)
icmp_packets = []

def detect_icmp(cfg, pkt, src, dst):
    # Check if this is ICMP
    if not hasattr(pkt, "icmp"):
        return

    # Get current time
    now = time.time()

    # Add this packet to our list
    icmp_packets.append((now, src))

    # Remove packets older than 1 second
    while icmp_packets and (now - icmp_packets[0][0]) > 1.0:
        icmp_packets.pop(0)

    # Count how many packets from this source in the last second
    threshold = cfg["thresholds"]["icmp_per_sec"]
    count = 0
    for timestamp, packet_src in icmp_packets:
        if packet_src == src:
            count += 1

    # If over threshold, emit event
    if count > threshold:
        emit_event(
            cfg,
            src=str(src) if src else "",
            dst=str(dst) if dst else "",
            proto="ICMP",
            rule_id="ICMP_RATE",
            severity="high",
            summary=f"ICMP echo rate {count}/s exceeds threshold {threshold}",
            metadata={"rate": count, "threshold": threshold},
        )
