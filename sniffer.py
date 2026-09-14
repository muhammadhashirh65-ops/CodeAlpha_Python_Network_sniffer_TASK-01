#!/usr/bin/env python3
"""
Basic Network Sniffer
CodeAlpha Cyber Security Internship - Task 1

A simple educational packet sniffer that captures live network traffic
on a chosen interface and prints useful information about each packet:
source/destination IP addresses, protocol, ports, and a preview of the
payload.

IMPORTANT:
- Raw packet capture requires elevated privileges.
    * Linux/macOS: run with sudo   ->  sudo python3 sniffer.py
    * Windows: run terminal as Administrator, and install Npcap first
      (https://npcap.com/) since Scapy relies on it for capture on Windows.
- Only run this on networks/machines you own or have explicit permission
  to monitor. Capturing traffic on networks you don't control or don't
  have authorization for may be illegal.

Usage:
    sudo python3 sniffer.py                     # sniff on default interface
    sudo python3 sniffer.py -i eth0              # sniff on a specific interface
    sudo python3 sniffer.py -c 50                # stop after 50 packets
    sudo python3 sniffer.py -f "tcp port 80"      # apply a BPF filter
    sudo python3 sniffer.py --no-payload          # hide payload preview
"""

import argparse
import datetime

try:
    from scapy.all import sniff, IP, IPv6, TCP, UDP, ICMP, ARP, Raw, get_if_list
except ImportError:
    raise SystemExit(
        "Scapy is not installed. Install it first with:\n"
        "    pip install scapy\n"
        "(On Linux you may also need libpcap: sudo apt install libpcap-dev)"
    )


# Map common port numbers to protocol names for a friendlier display
COMMON_PORTS = {
    20: "FTP-DATA", 21: "FTP", 22: "SSH", 23: "TELNET", 25: "SMTP",
    53: "DNS", 67: "DHCP", 68: "DHCP", 80: "HTTP", 110: "POP3",
    123: "NTP", 143: "IMAP", 443: "HTTPS", 445: "SMB", 3306: "MySQL",
    3389: "RDP", 5353: "mDNS", 8080: "HTTP-ALT",
}


def describe_port(port):
    return COMMON_PORTS.get(port, str(port))


def format_payload(packet, max_bytes=64):
    """Return a printable, truncated preview of the raw payload, if any."""
    if Raw not in packet:
        return None
    data = bytes(packet[Raw].load)
    preview = data[:max_bytes]
    # Render as printable ASCII, replacing non-printable bytes with '.'
    text = "".join(chr(b) if 32 <= b <= 126 else "." for b in preview)
    suffix = "..." if len(data) > max_bytes else ""
    return f"{text}{suffix}  ({len(data)} bytes total)"


def handle_packet(packet, show_payload=True):
    timestamp = datetime.datetime.now().strftime("%H:%M:%S")
    lines = []

    # --- Layer 3: IP / IPv6 / ARP ---
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        proto_num = packet[IP].proto
        ttl = packet[IP].ttl
        header = f"[{timestamp}] IPv4  {src_ip} -> {dst_ip}  (TTL={ttl})"
    elif IPv6 in packet:
        src_ip = packet[IPv6].src
        dst_ip = packet[IPv6].dst
        header = f"[{timestamp}] IPv6  {src_ip} -> {dst_ip}"
    elif ARP in packet:
        src_ip = packet[ARP].psrc
        dst_ip = packet[ARP].pdst
        op = "request" if packet[ARP].op == 1 else "reply"
        print(f"[{timestamp}] ARP   {src_ip} -> {dst_ip}  ({op})")
        return
    else:
        # Non-IP traffic (e.g. raw link-layer frames) — skip quietly
        return

    lines.append(header)

    # --- Layer 4: TCP / UDP / ICMP ---
    if TCP in packet:
        sport, dport = packet[TCP].sport, packet[TCP].dport
        flags = packet[TCP].flags
        lines.append(
            f"          TCP   {describe_port(sport)}({sport}) -> "
            f"{describe_port(dport)}({dport})  flags={flags}"
        )
    elif UDP in packet:
        sport, dport = packet[UDP].sport, packet[UDP].dport
        lines.append(
            f"          UDP   {describe_port(sport)}({sport}) -> "
            f"{describe_port(dport)}({dport})"
        )
    elif ICMP in packet:
        lines.append(
            f"          ICMP  type={packet[ICMP].type} code={packet[ICMP].code}"
        )
    else:
        lines.append(f"          Other IP protocol (proto={packet[IP].proto})"
                      if IP in packet else "          Other protocol")

    # --- Payload preview ---
    if show_payload:
        payload = format_payload(packet)
        if payload:
            lines.append(f"          Payload: {payload}")

    print("\n".join(lines))
    print("-" * 70)


def list_interfaces():
    print("Available interfaces:")
    for iface in get_if_list():
        print(f"  - {iface}")


def main():
    parser = argparse.ArgumentParser(description="Basic Python Network Sniffer")
    parser.add_argument("-i", "--interface", help="Network interface to sniff on (default: scapy's default)")
    parser.add_argument("-c", "--count", type=int, default=0, help="Number of packets to capture (0 = infinite)")
    parser.add_argument("-f", "--filter", default="", help="BPF filter string, e.g. 'tcp port 80'")
    parser.add_argument("--no-payload", action="store_true", help="Don't print payload preview")
    parser.add_argument("--list-interfaces", action="store_true", help="List available interfaces and exit")
    args = parser.parse_args()

    if args.list_interfaces:
        list_interfaces()
        return

    print("=" * 70)
    print(" Basic Network Sniffer — CodeAlpha Cyber Security Internship")
    print("=" * 70)
    print(f"Interface : {args.interface or '(default)'}")
    print(f"Filter    : {args.filter or '(none — capturing all traffic)'}")
    print(f"Count     : {'infinite (Ctrl+C to stop)' if args.count == 0 else args.count}")
    print("=" * 70)

    try:
        sniff(
            iface=args.interface if args.interface else None,
            filter=args.filter if args.filter else None,
            prn=lambda pkt: handle_packet(pkt, show_payload=not args.no_payload),
            count=args.count,
            store=False,
        )
    except PermissionError:
        raise SystemExit(
            "Permission denied. Packet capture requires elevated privileges.\n"
            "Try running again with 'sudo' (Linux/macOS) or as Administrator (Windows)."
        )
    except KeyboardInterrupt:
        print("\nStopped by user.")


if __name__ == "__main__":
    main()
