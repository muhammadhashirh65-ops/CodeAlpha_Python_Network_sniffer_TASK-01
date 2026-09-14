# CodeAlpha_NetworkSniffer

**Task 1 — Basic Network Sniffer**
CodeAlpha Cyber Security Internship

## 📖 Overview

A simple, educational Python packet sniffer built with [Scapy](https://scapy.net/).
It captures live network traffic on a chosen interface and prints readable
details for each packet: source/destination IP, protocol, ports, and a
preview of the payload. The goal is to understand how data flows through a
network and the structure of common protocols (IP, TCP, UDP, ICMP, ARP).

## ⚠️ Legal & Ethical Notice

Only run this tool on networks and devices **you own** or have **explicit
written permission** to monitor (e.g. your own home lab / test VM).
Capturing traffic on networks you don't control can be illegal and is a
violation of most acceptable-use policies. This project is for learning
purposes only.

## 🛠 Requirements

- Python 3.8+
- [Scapy](https://scapy.net/): `pip install scapy`
- **Linux/macOS**: run with `sudo` (raw sockets need root)
- **Windows**: install [Npcap](https://npcap.com/) first, then run your
  terminal as Administrator

## 🚀 Usage

```bash
# Basic capture on the default interface (Ctrl+C to stop)
sudo python3 sniffer.py

# Capture on a specific interface
sudo python3 sniffer.py -i eth0

# Stop automatically after 50 packets
sudo python3 sniffer.py -c 50

# Only capture HTTP traffic using a BPF filter
sudo python3 sniffer.py -f "tcp port 80"

# Hide the payload preview
sudo python3 sniffer.py --no-payload

# List available interfaces
python3 sniffer.py --list-interfaces
```

## 📋 Sample Output

```
[14:32:10] IPv4  192.168.1.15 -> 142.250.72.14  (TTL=64)
          TCP   54211(54211) -> HTTPS(443)  flags=PA
          Payload: ...\x17\x03\x03\x00\x2a...  (58 bytes total)
----------------------------------------------------------------------
[14:32:11] IPv4  192.168.1.15 -> 192.168.1.1  (TTL=64)
          UDP   54212(54212) -> DNS(53)
----------------------------------------------------------------------
```

## 🧠 What This Project Demonstrates

- Capturing live packets from a network interface with Scapy
- Parsing packet layers (Ethernet/IP/TCP/UDP/ICMP/ARP)
- Extracting source/destination addresses and ports
- Mapping common ports to protocol names
- Applying BPF (Berkeley Packet Filter) filter expressions
- Safely previewing raw payload bytes as printable text

## 📂 Files

- `sniffer.py` — main sniffer script
- `README.md` — this file

## ✅ Internship Submission Checklist

- [ ] Push this folder to GitHub as `CodeAlpha_NetworkSniffer`
- [ ] Record a short video walkthrough and post it on LinkedIn (tag @CodeAlpha)
- [ ] Share your internship progress on LinkedIn with the repo link
- [ ] Submit via the official CodeAlpha submission form
