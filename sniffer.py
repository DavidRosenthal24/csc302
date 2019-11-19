#!/usr/bin/python
from scapy.all import *

def print_pkt():
  pkt.show()
pkt = sniff(filter = 'icmp', timeout = 15)

for packet in pkt:
  print("Gotcha")
  print(packet[IP].src)
