"""
ARP detector - looks for ARP spoofing by checking if one IP has multiple MACs.
"""

from ..agent.logging import emit_event
import time

# Global list to store timestamps, IPs, and MACs
arp_records = []  # list of (timestamp, ip, mac)

def detect_arp(cfg, pkt, src, dst):
    # Check if this is an ARP packet
    if not hasattr(pkt, "arp"):
        return

    layer = pkt.arp

    # Get IP and MAC from the packet
    ip = None
    mac = None
    if hasattr(layer, "spa"):
        ip = layer.spa
    if hasattr(layer, "sha"):
        mac = layer.sha

    if not ip or not mac:
        return

    ip = str(ip)
    mac = str(mac)

    # Get current time
    now = time.time()

    # Get window size from config
    window = cfg["thresholds"]["arp_window_sec"]

    # Add this record to our list
    arp_records.append((now, ip, mac))

    # Remove old records outside the window
    while arp_records and (now - arp_records[0][0]) > window:
        arp_records.pop(0)

    # Count MACs per IP
    ip_to_macs = {}  # dict of ip -> list of macs
    for timestamp, rec_ip, rec_mac in arp_records:
        if rec_ip not in ip_to_macs:
            ip_to_macs[rec_ip] = []
        if rec_mac not in ip_to_macs[rec_ip]:
            ip_to_macs[rec_ip].append(rec_mac)

    # Check if this IP has multiple MACs
    macs_for_ip = ip_to_macs.get(ip, [])
    if len(macs_for_ip) >= 2:
        # Sort the MACs for nice output
        sorted_macs = sorted(macs_for_ip)
        emit_event(
            cfg,
            src=ip,
            dst=str(dst) if dst else "",
            proto="ARP",
            rule_id="ARP_MULTIMAC",
            severity="medium",
            summary=f"Multiple MACs observed for IP {ip} over {window}s window",
            metadata={"macs": sorted_macs, "window": window},
        )
