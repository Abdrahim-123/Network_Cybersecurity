#!/usr/bin/env python3
"""Quick debug script to check DNS packet parsing"""
import pyshark
import asyncio

loop = asyncio.new_event_loop()
asyncio.set_event_loop(loop)

cap = pyshark.FileCapture(
    r'c:\Users\mmr96\Desktop\Course Project\pcaps\dns_examples.pcapng',
    keep_packets=False
)

dns_count = 0
total = 0

for pkt in cap:
    total += 1
    if hasattr(pkt, 'dns'):
        dns_count += 1
        print(f"Packet {total}: DNS found!")
        qname = getattr(pkt.dns, 'qry_name', None) or getattr(pkt.dns, 'qry_name_raw', None)
        print(f"  Query name: {qname}")
    if total >= 50:
        break

print(f"\nTotal: {total}, DNS: {dns_count}")
cap.close()
