from scapy.all import *

a = IP()
a.dst = '73.13.161.87'
a.ttl = 1
b = ICMP()

def print_pkt(pkt):
  pkt.show()

pkt = sniff(filter = 'icmp')
reply = sr1(a/b)

for packet in pkt:
  print(packet[IP].scr)
print(reply.src)
