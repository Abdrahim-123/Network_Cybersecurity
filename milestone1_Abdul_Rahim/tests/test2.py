"""
Test 2: DNS entries present - UDP Protocol with DNS Detection

Purpose:
    This test validates the ability to detect DNS traffic and properly annotate it
    in the info field while maintaining the correct transport protocol (UDP).

Test Requirements (from Project PDF):
    1. Run capture_logger.py on dns_examples.pcapng
    2. Assert out_dns.jsonl exists
    3. Assert at least one packet has protocol == "UDP" AND info contains "DNS"

Key Design Decision:
    DNS packets are labeled with their transport protocol (UDP or TCP), not as "DNS".
    The DNS information is included in the "info" field to provide context about the
    packet's application-layer protocol while preserving transport layer accuracy.

Expected Outcome:
    The test should pass if the logger correctly identifies DNS queries running over
    UDP and includes "DNS" information in the info field.
"""

import json
import subprocess
import sys

# Step 1: Run the packet capture logger on the DNS examples pcap file
# This pcap contains DNS queries and responses, which typically use UDP port 53
subprocess.run([
    "python", "capture_logger.py",
    "--pcap", "tests/pcaps/dns_examples.pcapng",  # Input: pcap with DNS traffic
    "--out", "out_dns.jsonl",  # Output: separate file to avoid conflicts with test1
    "--overwrite"
], capture_output=True, text=True)

# Step 2: Verify the output file was created successfully
try:
    with open("out_dns.jsonl", "r") as f:
        output_lines = f.readlines()
except FileNotFoundError:
    print("Output file not found. Test failed.")
    sys.exit(1)

# Step 3: Search for at least one packet that is both UDP and contains DNS info
# We iterate through all lines to find a packet matching both criteria
found = False
for line in output_lines:
    try:
        obj = json.loads(line)
        # Check that protocol is UDP (transport layer) and DNS appears in info (application layer)
        if obj.get("protocol") == "UDP" and "DNS" in obj.get("info", ""):
            found = True
            break
    except json.JSONDecodeError:
        # Skip any malformed lines (shouldn't happen with correct implementation)
        continue

# Step 4: Verify we found at least one DNS over UDP packet
if not found:
    print("No DNS over UDP entry found in output. Test failed.")
    sys.exit(1)

print("All checks passed. Test succeeded.")