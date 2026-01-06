# Milestone 1 — Packet Capture Logger

This tool parses packets from a pcap/pcapng file or performs live capture, emitting one JSON object per packet on separate lines (JSONL).

## About this Tool

This tool helps you understand what's happening on a network. Networks communicate by sending tiny pieces of data called **packets**. This tool can do two things:

1.  **Analyze saved traffic:** You can give it a file (called a "pcap" file) that has saved network packets, and it will read them for you.
2.  **Live capture:** It can watch your computer's network connection in real-time and show you the packets as they go by.

It takes these packets, pulls out the most important information (like who sent it, who it's for, and what kind of data it is), and saves it in a simple, easy-to-read log file.

## Why Use This Tool?

You might use this tool for:

- **Learning:** See what kind of traffic common applications (like your web browser) create.
- **Debugging:** If you're building a network application, you can use this to see if it's sending and receiving data correctly.
- **Simple Security:** Get a basic idea of what devices are talking on your network.

## Installation

- Python 3.8+
- Install dependencies:
```
pip install -r requirements.txt
```
- **Live Capture on Windows:** Live network capture requires a special driver to let programs access raw network data. You will need to install **Npcap** (recommended) or WinPcap for this feature to work.

## Usage

Offline (pcap file):
```
python capture_logger.py --pcap tests/pcaps/basic_http.pcapng --out out.jsonl --overwrite
```

Live capture (requires admin/root and Npcap/WinPcap on Windows):
```
python capture_logger.py --live -i Ethernet --out live.jsonl --overwrite
```

Notes for live mode:
- Run the terminal as Administrator on Windows; install Npcap.
- Press Ctrl+C to stop; capture stops on the next packet and flushes output.

Common flags:
- `--raw`: include raw packet bytes as hex (`raw` field). Default: false.
- `--flush-every N`: flush output every N packets. Default: 50.

## Output Schema (per line)

Each line is a JSON object with:
```
{
	"ts": "ISO-8601 UTC timestamp",
	"eth_src": "aa:bb:cc:dd:ee:ff" | null,
	"eth_dst": "aa:bb:cc:dd:ee:ff" | null,
	"src_ip": "IPv4/IPv6" | null,
	"dst_ip": "IPv4/IPv6" | null,
	"src_port": number | null,
	"dst_port": number | null,
	"protocol": "TCP" | "UDP" | "ICMP" | "ARP" | "OTHER",
	"length": number,
	"info": string,
	"raw": string | false
}
```

Notes:
- When a DNS layer is present over UDP/TCP, the protocol remains `"UDP"` or `"TCP"`. The `info` field includes `DNS` and query name when available.
	- Example: `"info": "UDP 53 -> 53872 DNS query example.com."`

## Tests (Windows)

Two convenience scripts are provided under `tests/`:
```
tests/test1.bat   # Basic HTTP pcap — checks file exists, first-line JSON keys, and TCP present
tests/test2.bat   # DNS pcap — requires UDP + info containing "DNS"
```
Run from the project root:
```
./tests/test1.bat
./tests/test2.bat
./tests/test3.bat   # Manual Ctrl+C required
```

## Sample Output

See `sample_outputs/sample_output.jsonl`.

## Submission Notes

- Do not include local virtual environments (e.g., `venv/`) or large generated files. A `.gitignore` is included to help exclude these.
- Required files: `capture_log.py`, `capture_logger.py`, `requirements.txt`, `README.md`, `tests/`, `sample_outputs/`.
