#!/usr/bin/env python3
from scapy.all import *

print("SNIFFING PACKETS.........")

pkt = sniff(iface='docker0', filter='icmp', count = 10)

pkt.summary()
