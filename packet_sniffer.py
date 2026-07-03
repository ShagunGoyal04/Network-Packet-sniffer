#!/usr/bin/env python3
"""
Simple Network Packet Sniffer
==============================

A command-line packet sniffer built on Scapy. Captures live traffic on a
network interface, prints a summary line per packet, and can optionally
save everything to a .pcap file for later analysis in Wireshark.

REQUIREMENTS
------------
    pip install scapy --break-system-packages

USAGE
-----
    List available interfaces:
        sudo python3 packet_sniffer.py --list

    Sniff on default interface, all traffic:
        sudo python3 packet_sniffer.py

    Sniff on a specific interface:
        sudo python3 packet_sniffer.py -i eth0

    Filter by protocol (uses BPF filter syntax):
        sudo python3 packet_sniffer.py -f "tcp port 80"
        sudo python3 packet_sniffer.py -f "udp"
        sudo python3 packet_sniffer.py -f "icmp"

    Save captured packets to a pcap file:
        sudo python3 packet_sniffer.py -w capture.pcap

    Limit number of packets captured:
        sudo python3 packet_sniffer.py -c 100

    Show full packet detail (verbose) instead of one-line summaries:
        sudo python3 packet_sniffer.py -v

NOTES
-----
    - Raw packet capture requires elevated privileges. Run with sudo on
      Linux/macOS, or as Administrator on Windows.
    - This tool only captures traffic visible to the host running it
      (i.e. traffic to/from this machine, or all traffic on the segment
      if the interface is in promiscuous mode and the network allows it).
    - Only sniff on networks you own or have explicit permission to
      monitor. Capturing traffic on networks without authorization may
      be illegal in your jurisdiction.
"""

import argparse
import datetime
import sys

try:
    from scapy.all import sniff, wrpcap, IP, IPv6, TCP, UDP, ICMP, ARP, Ether, get_if_list
except ImportError:
    print("Scapy is not installed. Install it with:")
    print("    pip install scapy --break-system-packages")
    sys.exit(1)


captured_packets = []


def describe_packet(pkt):
    """Return a short, human-readable one-line summary of a packet."""
    ts = datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3]

    # Layer 3 info
    if IP in pkt:
        src, dst = pkt[IP].src, pkt[IP].dst
    elif IPv6 in pkt:
        src, dst = pkt[IPv6].src, pkt[IPv6].dst
    elif ARP in pkt:
        src, dst = pkt[ARP].psrc, pkt[ARP].pdst
    else:
        src, dst = (pkt[Ether].src, pkt[Ether].dst) if Ether in pkt else ("?", "?")

    # Layer 4 / protocol info
    if TCP in pkt:
        proto = "TCP"
        sport, dport = pkt[TCP].sport, pkt[TCP].dport
        flags = pkt[TCP].flags
        extra = f"{sport} -> {dport} [{flags}]"
    elif UDP in pkt:
        proto = "UDP"
        sport, dport = pkt[UDP].sport, pkt[UDP].dport
        extra = f"{sport} -> {dport}"
    elif ICMP in pkt:
        proto = "ICMP"
        extra = f"type={pkt[ICMP].type} code={pkt[ICMP].code}"
    elif ARP in pkt:
        proto = "ARP"
        op = "who-has" if pkt[ARP].op == 1 else "is-at" if pkt[ARP].op == 2 else str(pkt[ARP].op)
        extra = op
    else:
        proto = pkt.lastlayer().name if pkt else "?"
        extra = ""

    length = len(pkt)
    return f"[{ts}] {proto:<5} {src:>21} -> {dst:<21} {extra:<20} len={length}"


def handle_packet(pkt, verbose=False, store=False):
    if store:
        captured_packets.append(pkt)

    if verbose:
        pkt.show()
        print("-" * 70)
    else:
        print(describe_packet(pkt))


def list_interfaces():
    print("Available interfaces:")
    for iface in get_if_list():
        print(f"  - {iface}")


def main():
    parser = argparse.ArgumentParser(
        description="Simple network packet sniffer built on Scapy.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("-i", "--iface", help="Network interface to sniff on (default: scapy's default)")
    parser.add_argument("-f", "--filter", help='BPF filter string, e.g. "tcp port 80", "udp", "icmp"')
    parser.add_argument("-c", "--count", type=int, default=0, help="Number of packets to capture (0 = infinite)")
    parser.add_argument("-w", "--write", help="Write captured packets to this pcap file")
    parser.add_argument("-v", "--verbose", action="store_true", help="Show full packet details instead of summaries")
    parser.add_argument("--list", action="store_true", help="List available network interfaces and exit")
    args = parser.parse_args()

    if args.list:
        list_interfaces()
        return

    store = bool(args.write)

    print("Starting capture... (Ctrl+C to stop)")
    if args.iface:
        print(f"  Interface : {args.iface}")
    if args.filter:
        print(f"  Filter    : {args.filter}")
    if args.count:
        print(f"  Count     : {args.count}")
    print("-" * 70)

    try:
        sniff(
            iface=args.iface,
            filter=args.filter,
            count=args.count if args.count > 0 else 0,
            prn=lambda pkt: handle_packet(pkt, verbose=args.verbose, store=store),
            store=False,
        )
    except PermissionError:
        print("\nPermission denied. Try running with sudo (Linux/macOS) or as Administrator (Windows).")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\nCapture stopped by user.")
    finally:
        if store and captured_packets:
            wrpcap(args.write, captured_packets)
            print(f"\nSaved {len(captured_packets)} packets to {args.write}")


if __name__ == "__main__":
    main()
