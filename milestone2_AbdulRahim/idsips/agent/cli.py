"""
idsips.agent.cli
This is the command-line tool for the IDS/IPS agent.
It can process pcap files or do live capture.
"""

import argparse
import sys
import yaml
import time

# Import our own modules
from .signals import install_sigint_handler
from .logging import emit_ops
from . import capture as cap
from ..detectors.dns import detect_dns
from ..detectors.icmp import detect_icmp
from ..detectors.arp import detect_arp
from ..detectors.http import detect_http

# This is for stopping the program when user presses Ctrl+C
STOP = install_sigint_handler()

def load_cfg(path="config.yaml"):
    # Open the config file and read it as YAML
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)

def process_packet(cfg, pkt):
    # This function looks at each packet and runs detectors
    try:
        proto = "OTHER"  # default protocol
        src = None
        dst = None

        # Check if it's an IP packet
        if hasattr(pkt, "ip"):
            # Get the protocol from the packet
            if hasattr(pkt, "highest_layer"):
                proto = pkt.highest_layer
            elif hasattr(pkt, "transport_layer"):
                proto = pkt.transport_layer
            else:
                proto = "OTHER"
            # Get source and destination
            if hasattr(pkt.ip, "src"):
                src = pkt.ip.src
            if hasattr(pkt.ip, "dst"):
                dst = pkt.ip.dst

        # Check if it's ARP
        elif hasattr(pkt, "arp"):
            proto = "ARP"
            if hasattr(pkt.arp, "spa"):
                src = pkt.arp.spa
            if hasattr(pkt.arp, "tpa"):
                dst = pkt.arp.tpa

        # Check if it's ICMP
        elif hasattr(pkt, "icmp"):
            proto = "ICMP"

        # Check if it's DNS
        elif hasattr(pkt, "dns"):
            proto = "DNS"

        # Now run the detectors based on config
        if cfg["rules"].get("dns_suspicious"):
            detect_dns(cfg, pkt, src, dst)
        if cfg["rules"].get("icmp_flood"):
            detect_icmp(cfg, pkt, src, dst)
        if cfg["rules"].get("arp_spoof"):
            detect_arp(cfg, pkt, src, dst)
        if cfg["rules"].get("http_keyword"):
            detect_http(cfg, pkt, src, dst)

    except Exception as e:
        # If something goes wrong, log an error
        emit_ops(cfg, "ERROR", "decoder", "packet_error", {"error": str(e)})

def cmd_pcap(args):
    # Load the config
    cfg = load_cfg(args.config)
    # Log that we started
    emit_ops(cfg, "INFO", "runner", "start_pcap", {"file": args.pcap})
    print(f"Processing PCAP: {args.pcap}")

    try:
        # Open the pcap file and read packets
        with cap.FileAdapter(args.pcap) as reader:
            for pkt in reader.stream():
                # Stop if user pressed Ctrl+C
                if STOP["flag"]:
                    break
                # Process each packet
                process_packet(cfg, pkt)
    finally:
        # Always log shutdown
        emit_ops(cfg, "INFO", "runner", "shutdown", {"reason": "EOF_or_SIGINT"})

    print("PCAP processing completed successfully.")
    return 0

def cmd_live(args):
    # Load config
    cfg = load_cfg(args.config)
    # Log start
    emit_ops(cfg, "INFO", "runner", "start_live", {"iface": args.iface, "dry_run": args.dry_run})

    # Check if dry run
    is_dry = args.dry_run or cfg.get("capture", {}).get("dry_run", False)
    if is_dry:
        mode = "dry-run"
    else:
        mode = "live"

    print(f"Starting {mode} capture on interface: {args.iface}")
    print("Press Ctrl+C to stop...")

    try:
        if is_dry:
            # Just wait in dry run
            while not STOP["flag"]:
                time.sleep(0.2)
        else:
            # Real capture
            with cap.LiveAdapter(args.iface) as reader:
                for pkt in reader.stream():
                    if STOP["flag"]:
                        break
                    process_packet(cfg, pkt)
    finally:
        # Log shutdown
        emit_ops(cfg, "INFO", "runner", "shutdown", {"reason": "SIGINT" if STOP["flag"] else "normal"})

    print("\nCapture stopped successfully.")
    return 0

def main(argv=None):
    # Set up the command line arguments
    p = argparse.ArgumentParser(prog="idsips-agent")
    sub = p.add_subparsers(dest="cmd", required=True)

    # Common arguments
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--config", default="config.yaml", help="Path to YAML config")

    # PCAP command
    p_pcap = sub.add_parser("pcap", parents=[common], help="Process a pcap file")
    p_pcap.add_argument("--pcap", required=True, help="Path to .pcap/.pcapng")
    p_pcap.set_defaults(func=cmd_pcap)

    # Live command
    p_live = sub.add_parser("live", parents=[common], help="Live capture from an interface")
    p_live.add_argument("--iface", default="lo", help="Network interface (default: loopback)")
    p_live.add_argument("--dry-run", action="store_true", help="Loop until SIGINT without capturing (CI-friendly)")
    p_live.set_defaults(func=cmd_live)

    # Parse and run
    args = p.parse_args(argv)
    return args.func(args)

if __name__ == "__main__":
    sys.exit(main())
