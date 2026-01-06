"""
Capture adapters for reading packets from files or live interfaces.
"""

from pathlib import Path
import datetime
import pyshark
import asyncio

class LiveAdapter:
    def __init__(self, interface):
        self.interface = interface
        self.cap = None

    def __enter__(self):
        # PyShark needs an event loop
        try:
            asyncio.get_event_loop()
        except RuntimeError:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
        self.cap = pyshark.LiveCapture(interface=self.interface)
        return self

    def __exit__(self, exc_type, exc, tb):
        try:
            if self.cap:
                self.cap.close()
        except:
            pass

    def stream(self):
        # Yield packets one by one
        for pkt in self.cap.sniff_continuously():
            yield pkt

class FileAdapter:
    def __init__(self, pcap_path):
        self.path = str(Path(pcap_path).resolve())
        self.cap = None

    def __enter__(self):
        # Same event loop check
        try:
            asyncio.get_event_loop()
        except RuntimeError:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
        self.cap = pyshark.FileCapture(self.path, keep_packets=False)
        return self

    def __exit__(self, exc_type, exc, tb):
        try:
            if self.cap:
                self.cap.close()
        except:
            pass

    def stream(self):
        # Yield packets from file
        for pkt in self.cap:
            yield pkt

def now_iso():
    # Current time
    return datetime.datetime.now(datetime.timezone.utc).isoformat()

def normalize_basics(pkt):
    # Create basic info dict from packet
    d = {"ts": now_iso(), "src": None, "dst": None, "proto": "OTHER", "length": None, "info": ""}

    try:
        # Check for IP
        if hasattr(pkt, "ip"):
            if hasattr(pkt.ip, "src"):
                d["src"] = pkt.ip.src
            if hasattr(pkt.ip, "dst"):
                d["dst"] = pkt.ip.dst

        # Get length
        if hasattr(pkt, "length"):
            d["length"] = pkt.length
        elif hasattr(pkt, "frame"):
            if hasattr(pkt.frame, "len"):
                d["length"] = pkt.frame.len

        # Determine protocol
        proto = "OTHER"
        if hasattr(pkt, "highest_layer"):
            proto = pkt.highest_layer
        elif hasattr(pkt, "transport_layer"):
            proto = pkt.transport_layer

        if hasattr(pkt, "dns"):
            d["proto"] = "DNS"
            qname = None
            if hasattr(pkt.dns, "qry_name"):
                qname = pkt.dns.qry_name
            elif hasattr(pkt.dns, "qry_name_raw"):
                qname = pkt.dns.qry_name_raw
            if qname:
                d["info"] = "DNS query " + str(qname)

        elif hasattr(pkt, "icmp"):
            d["proto"] = "ICMP"
            typ = None
            if hasattr(pkt.icmp, "type"):
                typ = pkt.icmp.type
            d["info"] = "ICMP type=" + str(typ) if typ is not None else "ICMP"

        elif hasattr(pkt, "arp"):
            d["proto"] = "ARP"
            spa = None
            tpa = None
            if hasattr(pkt.arp, "spa"):
                spa = pkt.arp.spa
            if hasattr(pkt.arp, "tpa"):
                tpa = pkt.arp.tpa
            d["src"] = d["src"] or spa
            d["dst"] = d["dst"] or tpa
            if spa and tpa:
                d["info"] = "ARP who-has " + str(tpa) + "? tell " + str(spa)

        elif hasattr(pkt, "http"):
            d["proto"] = "HTTP"
            host = ""
            uri = ""
            if hasattr(pkt.http, "host"):
                host = pkt.http.host
            if hasattr(pkt.http, "request_uri"):
                uri = pkt.http.request_uri
            d["info"] = "HTTP " + host + uri if (host or uri) else "HTTP"

        elif proto in ["TCP", "UDP"]:
            d["proto"] = proto
        else:
            d["proto"] = "OTHER"

    except:
        pass

    return d

def log_packet_ops(cfg, ops_logger, pkt):
    # Log packet info if enabled
    try:
        if cfg.get("capture", {}).get("log_every_packet", False):
            d = normalize_basics(pkt)
            ops_logger(cfg, level="DEBUG", component="capture", msg="packet", kv=d)
    except:
        pass
