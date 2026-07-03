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


Intern Id - CITS2932



