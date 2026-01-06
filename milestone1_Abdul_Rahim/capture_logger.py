"""
Milestone 1 - Packet Capture Logger

Author: [Your Name]
Course: [Course Number]
Date: November 2025

Description:
    This program parses network packets from pcap files or performs live network capture,
    outputting structured data in JSON Lines (JSONL) format. Each line represents one packet
    with extracted information including timestamp, MAC addresses, IP addresses, ports,
    protocol type, and contextual information.

Key Features:
    - Offline pcap/pcapng file parsing
    - Live network interface capture (requires admin/root privileges)
    - Graceful shutdown on Ctrl+C (SIGINT) with output flushing
    - Support for multiple protocols: TCP, UDP, ICMP, ARP, DNS
    - Optional raw packet data export in hexadecimal format

Design Decisions:
    - DNS packets retain their transport protocol (UDP/TCP) in the "protocol" field,
      with DNS query information included in the "info" field for clarity
    - JSONL format (one JSON object per line) allows efficient streaming and processing
    - Periodic buffer flushing ensures data safety during long captures
"""

import argparse
import json
import signal
import sys
from datetime import datetime, timezone
import os

# Import scapy components for packet parsing and capture
try:
    from scapy.all import (
        sniff, rdpcap, Ether, IP, IPv6, TCP, UDP, ICMP, ARP, DNS
    )
except ImportError:
    print(
        "Error: The 'scapy' library is required. Please install it with 'pip install scapy'",
        file=sys.stderr
    )
    sys.exit(1)

# Global counters and flags
PACKET_COUNT = 0  # Total packets processed
SHUTDOWN = False  # Flag set by SIGINT (Ctrl+C) for graceful shutdown

def iso_ts(ts=None):
    """
    Convert a timestamp to ISO 8601 format with UTC timezone (Z suffix).
    
    Args:
        ts: Unix timestamp (float/int) from packet, or None for current time
    
    Returns:
        ISO 8601 string with microsecond precision, e.g., "2025-11-16T12:34:56.789012Z"
    """
    if ts is None:
        dt = datetime.now(timezone.utc)
    else:
        ts_float = float(ts)
        dt = datetime.fromtimestamp(ts_float, timezone.utc)
    return dt.isoformat(timespec='microseconds').replace('+00:00','Z')

def extract_packet_info_scapy(pkt):
    """
    Extract relevant information from a scapy packet and return as a dictionary.
    
    Parses Ethernet, IP, and transport layer (TCP/UDP/ICMP) headers, plus ARP and DNS.
    Protocol-specific handling:
    - ARP: extracts sender/target IPs
    - TCP/UDP: extracts ports and flags; checks for DNS layer
    - DNS: keeps protocol as TCP/UDP but annotates info with query name
    - ICMP: basic ICMP labeling
    
    Args:
        pkt: A scapy packet object
    
    Returns:
        dict with keys: ts, eth_src, eth_dst, src_ip, dst_ip, src_port, dst_port,
                        protocol, length, info
    """
    # Initialize output dictionary with default/null values
    info = {
        "ts": iso_ts(pkt.time) if hasattr(pkt, 'time') else iso_ts(),
        "eth_src": None, "eth_dst": None,
        "src_ip": None, "dst_ip": None,
        "src_port": None, "dst_port": None,
        "protocol": "OTHER",  # Default if no recognized protocol
        "length": len(pkt),
        "info": ""
    }
    
    # Extract Ethernet layer source and destination MAC addresses
    try:
        if Ether in pkt:
            eth = pkt[Ether]
            info["eth_src"] = eth.src
            info["eth_dst"] = eth.dst
    except Exception:
        pass  # Some packets may not have Ethernet layer

    # ARP Protocol: Address Resolution Protocol
    if ARP in pkt:
        arp = pkt[ARP]
        info["protocol"] = "ARP"
        info["src_ip"] = arp.psrc  # Sender protocol address
        info["dst_ip"] = arp.pdst  # Target protocol address
        info["info"] = f"ARP {arp.op} {arp.psrc} -> {arp.pdst}"
        return info

    # IP / IPv6 layer present: extract network and transport layer info
    if IP in pkt or IPv6 in pkt:    
        ip_layer = pkt[IP] if IP in pkt else pkt[IPv6]
        info["src_ip"] = ip_layer.src
        info["dst_ip"] = ip_layer.dst

        # TCP Protocol: Transmission Control Protocol
        if TCP in pkt:
            tcp = pkt[TCP]
            info["protocol"] = "TCP"
            info["src_port"] = int(tcp.sport)
            info["dst_port"] = int(tcp.dport)
            
            # Parse TCP flags to identify connection state (SYN, ACK, FIN, RST, etc.)
            flag_st = str(tcp.flags)
            if 'S' in flag_st and 'A' not in flag_st:
                info["info"] = "TCP SYN"  # Connection initiation
            elif 'S' in flag_st and 'A' in flag_st:
                info["info"] = "TCP SYN-ACK"  # Connection acknowledgment
            elif 'F' in flag_st:
                info["info"] = "TCP FIN"  # Connection termination
            elif 'R' in flag_st:
                info["info"] = "TCP RST"  # Connection reset
            else:
                info["info"] = f"TCP {flag_st if flag_st else ''}"
            
            # DNS over TCP: keep protocol as TCP; annotate info with DNS query
            # Design Note: We maintain transport protocol accuracy while adding
            # application-layer context. This helps distinguish DNS-over-TCP from
            # regular TCP traffic without losing transport layer information.
            if DNS in pkt:
                dns = pkt[DNS]
                q = dns.qd.qname.decode() if dns.qd else None
                info["info"] += (f" DNS query {q}" if q else " DNS")
            return info

        # UDP Protocol: User Datagram Protocol
        if UDP in pkt:
            udp = pkt[UDP]
            info["protocol"] = "UDP"
            info["src_port"] = udp.sport
            info["dst_port"] = udp.dport
            info["info"] = f"UDP {udp.sport} -> {udp.dport}"
            
            # DNS over UDP: keep protocol as UDP; annotate info with DNS query
            # Design Note: Most DNS traffic uses UDP port 53. By preserving the UDP
            # protocol label and adding DNS context to info, we maintain both transport
            # and application layer visibility in a single packet record.
            if DNS in pkt:
                dns = pkt[DNS] 
                q = dns.qd.qname.decode() if dns.qd else None
                info["info"] += (f" DNS query {q}" if q else " DNS")
            return info
        
        # ICMP Protocol: Internet Control Message Protocol (ping, etc.)
        if ICMP in pkt:
            info["protocol"] = "ICMP"
            info["info"] = f"ICMP"
            return info
    
    # Fallback for unrecognized packet types: use scapy's summary
    info["info"] = pkt.summary() if hasattr(pkt, 'summary') else "Unknown Packet"
    return info

def handle_packet(pkt, output, args, is_live=False):
    """
    Process a single packet: extract info, optionally add raw bytes, write JSON line.
    
    Args:
        pkt: scapy packet object
        output: file handle for writing JSON output
        args: command-line arguments (includes raw flag, flush_every)
        is_live: bool indicating live capture (enables progress logging)
    """
    global PACKET_COUNT
    PACKET_COUNT += 1

    # Print progress every 1000 packets during live capture
    if is_live and PACKET_COUNT % 1000 == 0:
        print(f"Captured {PACKET_COUNT} packets...", file=sys.stderr)
    
    # Extract packet information into dictionary
    try:
        data = extract_packet_info_scapy(pkt)
    except Exception as e:
        print(f"Error processing packet: {e}", file=sys.stderr)
        return
    
    # Optionally include raw packet bytes as hex string
    if args.raw:
        data["raw"] = bytes(pkt).hex()
    else:
        data["raw"] = False
    
    # Write JSON line (JSONL format: one object per line)
    output.write(json.dumps(data) + "\n")
    
    # Flush output buffer periodically to ensure data is written to disk
    if PACKET_COUNT % args.flush_every == 0:
        output.flush()


def pcap_mode(infile, out_fh, args):
    """
    Read and process packets from a pcap/pcapng file.
    
    Loads all packets into memory, then processes each one. Supports graceful
    shutdown via Ctrl+C by checking the SHUTDOWN flag.
    
    Args:
        infile: path to pcap/pcapng file
        out_fh: file handle for output
        args: command-line arguments
    """
    packets = rdpcap(infile)  # Load all packets from file
    for pkt in packets:
        if SHUTDOWN:  # Check if user pressed Ctrl+C
            break
        handle_packet(pkt, out_fh, args)
    out_fh.flush()  # Ensure all output is written before exit


def live_mode(interface, out_fh, args):
    """
    Capture packets live from a network interface.
    
    Uses scapy's sniff() function to capture packets in real-time. Packets are
    processed immediately (store=False) to minimize memory usage. Stops when
    SHUTDOWN flag is set by Ctrl+C.
    
    Args:
        interface: name of network interface (e.g., "Wi-Fi", "eth0")
        out_fh: file handle for output
        args: command-line arguments
    """
    try:
        # sniff() captures packets and calls handle_packet for each one
        # store=False: don't keep packets in memory (streaming mode)
        # stop_filter: function that returns True when capture should stop
        sniff(
            iface=interface,
            prn=lambda pkt: handle_packet(pkt, out_fh, args, is_live=True),
            store=False,
            stop_filter=lambda x: SHUTDOWN
        )
    finally:
        out_fh.flush()  # Ensure output is written even if interrupted

def graceful_shutdown(signum, frame):
    """
    Signal handler for SIGINT (Ctrl+C) to enable graceful shutdown.
    
    Sets the SHUTDOWN flag which is checked by pcap_mode loop and live_mode
    stop_filter. This allows the program to finish processing the current
    packet and flush output before exiting.
    
    Args:
        signum: signal number (unused)
        frame: current stack frame (unused)
    """
    global SHUTDOWN
    print(f"\nShutdown signal received. Processed {PACKET_COUNT} packets. Exiting...", file=sys.stderr)
    SHUTDOWN = True

def main():
    """
    Main entry point: parse arguments and run either pcap or live capture mode.
    
    Command-line interface supports:
    - --pcap: offline analysis of pcap/pcapng files
    - --live: real-time capture from network interface (requires admin/root)
    - --out: output file path (default: capture_log.jsonl)
    - --overwrite: overwrite output file instead of appending
    - --raw: include raw packet bytes as hex in output
    - --flush-every: flush output buffer every N packets
    """
    # Set up argument parser with mutually exclusive mode selection
    parser = argparse.ArgumentParser(description="Capture and log network packets.")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--pcap", type=str, help="Read packets from a pcap/pcapng file")
    group.add_argument("--live", action="store_true", help="Capture live packets from an interface")
    parser.add_argument("-i", "--interface", type=str, default=None, help="Network interface for live capture")
    parser.add_argument("--out", default="capture_log.jsonl", help="Output log file (default: capture_log.jsonl)")
    parser.add_argument("--overwrite", action="store_true", help="Overwrite output file if it exists")
    parser.add_argument("--raw", action="store_true", help="Include raw packet data in hex format")
    parser.add_argument("--flush-every", type=int, default=50, help="Flush output every N packets")

    args = parser.parse_args()

    # Register signal handler for graceful Ctrl+C shutdown
    signal.signal(signal.SIGINT, graceful_shutdown)

    # PCAP mode: process packets from file
    if args.pcap:
        with open(args.out, "w" if args.overwrite else "a") as out_fh:
            pcap_mode(args.pcap, out_fh, args)
        
        print(f"Processed {PACKET_COUNT} packets from {args.pcap}", file=sys.stderr)
    
    # Live capture mode: requires admin/root privileges
    elif args.live:
        # Check for root/admin privileges (Unix systems only)
        if hasattr(os, 'geteuid') and os.geteuid() != 0:
            print("Error: Live capture requires root privileges. Please run as root or use sudo.", file=sys.stderr)
            print("use --pcap mode for offline analysis instead if you encounter permission issues.", file=sys.stderr)
            sys.exit(1)
        elif not hasattr(os, 'geteuid'):
            # Windows or other platforms: warn but continue (requires Npcap/WinPcap)
            print("Warning: Unable to verify root privileges on this platform. Ensure you have the necessary permissions for live capture.", file=sys.stderr)
            print("use --pcap mode for offline analysis instead if you encounter permission issues.", file=sys.stderr)
        
        # Validate interface parameter
        if not args.interface:
            print("Error: --interface is required for live capture", file=sys.stderr)
            sys.exit(1)
        
        # Start live capture
        with open(args.out, "w" if args.overwrite else "a") as out_fh:
            live_mode(args.interface, out_fh, args)


if __name__ == "__main__":
    main()
