from scapy.all import *

a = IP()
a.dst = '73.13.161.87'
a.ttl = 1
b = ICMP()

def print_pkt(pkt):
  pkt.show()
reply = sr1(a/b)
pkt = sniff(filter = 'icmp')

for packet in pkt:
  print(packet[IP].scr)
print(reply.src)
