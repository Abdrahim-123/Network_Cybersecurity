"""
Test 1: Basic pcap parse - TCP Protocol Detection

Purpose:
    This test validates the core functionality of parsing pcap files and extracting
    packet information. It specifically checks for TCP protocol detection.

Test Requirements (from Project PDF):
    1. Run capture_logger.py on basic_http.pcapng
    2. Assert out.jsonl exists
    3. Assert first line is valid JSON with required keys: ts, src_ip, dst_ip, protocol
    4. Assert at least one packet has protocol == "TCP"

Expected Outcome:
    The test should pass if the logger correctly parses the HTTP traffic pcap file,
    outputs valid JSONL format, and identifies TCP packets.
"""

import json
import subprocess
import sys

# Step 1: Run the packet capture logger on the basic HTTP pcap file
# This pcap contains HTTP traffic which uses TCP as its transport protocol
result = subprocess.run(
    [
        "python", 
        "capture_logger.py", 
        "--pcap",
        "tests/pcaps/basic_http.pcapng",  # Input: pcap file with HTTP/TCP traffic
        "--out",
        "out.jsonl",  # Output: JSON Lines format (one JSON object per line)
        "--overwrite"  # Overwrite any existing output file
    ],
    capture_output=True,
    text=True
)

# Step 2: Verify the output file was created successfully
try:
    with open("out.jsonl", "r") as f:
        output_lines = f.readlines()
except FileNotFoundError:
    print("Output file not found. Test failed.")
    sys.exit(1)

# Step 3: Validate the first line contains valid JSON with all required keys
# Each packet should have timestamp, source IP, destination IP, and protocol
try:
    first_entry = json.loads(output_lines[0])
    required = ["ts", "src_ip", "dst_ip", "protocol"]
    for key in required:
        if key not in first_entry:
            print(f"Missing key '{key}' in output. Test failed.")
            sys.exit(1)
except json.JSONDecodeError:
    print("First line is not valid JSON. Test failed.")
    sys.exit(1)

# Step 4: Verify at least one packet is identified as TCP protocol
# HTTP traffic runs over TCP, so we expect to find TCP packets in the output
tcp_found = any('"protocol": "TCP"' in line for line in output_lines)
if not tcp_found:
    print("No TCP protocol entry found in output. Test failed.")
    sys.exit(1)

print("All checks passed. Test succeeded.")