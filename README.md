# Network Analysis & Intrusion Detection System (IDS)

This repository documents the development of a custom network security toolset, progressing from raw packet capture to a functional Mini-IDS/IPS (Intrusion Detection and Prevention System) with SIEM capabilities.

## 🏆 Certification

This project was completed as part of the ShiftKey Labs Cybersecurity program.

![Certificate of Completion](certificate.png)

*[Click here to view the full PDF Certificate](CyberSec_Shiftkey.pdf)*

---

## 📖 Project Context

This project is divided into two distinct developmental phases, simulating the lifecycle of building network security tools from scratch:

### Phase 1: The Foundation — Packet Capture Logger

The initial phase focused on visibility. I built a tool capable of parsing raw network traffic from `pcap` files or performing live captures. This tool acts as the "eyes" of the system, extracting critical metadata (Source/Dest IP, Ports, Protocols) and serializing them into a structured JSONL format for easy analysis.

### Phase 2: The Intelligence — Mini IDS/IPS & SIEM

Building on the packet parsing capabilities, the second phase introduced logic and detection. I developed a lightweight IDS using `PyShark` to analyze packets against specific threat signatures. The system includes:

* **An Agent:** Applies detectors (like DNS suspicious names or ARP spoofing) to traffic.
* **A Mini-SIEM:** Aggregates logs, generates alerts, and correlates events to identify high-volume attacks.

---

## 🛠️ Technical Architecture

### 1. Packet Capture Engine (Milestone 1)

Designed for learning and debugging, this module helps understand network traffic flow by creating easy-to-read logs.

* **Inputs:** Live Ethernet/WiFi capture or Offline `.pcap`/`.pcapng` files.
* **Output:** JSON Objects containing timestamps, protocol details (TCP/UDP/ICMP), and payload info.

### 2. Mini IDS/IPS (Milestone 2)

A rule-based engine that processes the traffic to identify anomalies.

**Detectors implemented:**

* **DNS Suspicious Names:** Flags high entropy or unusually long domain names.
* **ARP Multi-MAC:** Detects ARP spoofing by monitoring IP-to-MAC associations.
* **ICMP Rate:** Triggers alerts on ICMP flooding (potential DDoS).
* **HTTP Keyword:** Searches for specific keywords in URIs.

---

## 💻 Tech Stack

* **Language:** Python 3.8+
* **Packet Analysis:** Wireshark, TShark, PyShark
* **Drivers:** Npcap (Windows)
* **Data Serialization:** JSONL (JSON Lines)

---

## 🚀 Usage Snapshot

### Running the Capture Logger (Phase 1)
```bash
python capture_logger.py --live -i Ethernet --out live.jsonl
```

### Running the IDS Agent (Phase 2)
```bash
python -m idsips.agent.cli live --iface Ethernet
```

### Running the Mini-SIEM Analysis
```bash
python -m idsips.siem.mini_siem --timeline
```

---

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 🤝 Acknowledgments

Special thanks to ShiftKey Labs for providing the cybersecurity training program that made this project possible.
