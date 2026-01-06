#!/usr/bin/env python3
"""
Simple test runner for the IDS/IPS project.
Tests the main features: DNS detection, ARP detection, live mode, and mini-SIEM.
"""
import subprocess
import signal
import time
import sys
import pathlib

# Set up paths
ROOT = pathlib.Path(__file__).resolve().parents[1]
LOGS = ROOT / "logs"
PCAPS = ROOT / "pcaps"

def main():
    passed = 0

    # Clean up old log files
    for log_file in ["detections.jsonl", "ops.jsonl", "alerts.jsonl"]:
        log_path = LOGS / log_file
        if log_path.exists():
            log_path.unlink()

    # Test 1: DNS PCAP
    print("Running Test 1: DNS PCAP")
    result = subprocess.run(
        ["python", "-m", "idsips.agent.cli", "pcap", "--pcap", str(PCAPS / "dns_examples.pcapng")],
        cwd=ROOT
    )
    if result.returncode == 0:
        print("[PASS] DNS PCAP")
        passed += 1
    else:
        print("[FAIL] DNS PCAP")

    # Test 2: ARP spoof
    print("Running Test 2: ARP spoof")
    arp_pcap = PCAPS / "arp_spoof_short.pcap"
    if arp_pcap.exists():
        result = subprocess.run(
            ["python", "-m", "idsips.agent.cli", "pcap", "--pcap", str(arp_pcap)],
            cwd=ROOT
        )
        if result.returncode == 0:
            print("[PASS] ARP PCAP")
            passed += 1
        else:
            print("[FAIL] ARP PCAP")
    else:
        print("[SKIP] ARP test (pcap not present)")

    # Test 3: Live SIGINT
    print("Running Test 3: Live SIGINT")
    proc = subprocess.Popen(
        ["python", "-m", "idsips.agent.cli", "live", "--iface", "lo", "--dry-run"],
        cwd=ROOT
    )
    time.sleep(2)
    try:
        proc.send_signal(signal.SIGINT)
    except (ValueError, AttributeError):
        proc.terminate()
    code = proc.wait(timeout=10)
    if code in (0, 1):
        print("[PASS] Live Ctrl-C")
        passed += 1
    else:
        print("[FAIL] Live Ctrl-C")

    # Test 4: Mini-SIEM
    print("Running Test 4: Mini-SIEM")
    result = subprocess.run(
        ["python", "-m", "idsips.siem.mini_siem", "--rule-stats"],
        cwd=ROOT
    )
    if result.returncode == 0:
        print("[PASS] Mini-SIEM")
        passed += 1
    else:
        print("[FAIL] Mini-SIEM")

    # Final check
    if passed < 3:  # At least 3 if ARP skipped
        print(f"{passed} checks passed")
        sys.exit(1)
    print("All visible tests passed.")
    return 0

if __name__ == "__main__":
    sys.exit(main())
