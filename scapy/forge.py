# forged packet
from scapy.all import *

mypacket = IP()
mypacket.show()
print mypacket.src

print ""

# slack of an IP and TCP packet
packet = mypacket/TCP()
packet.show()

# manipulate TCP parameters
packet.ttl = 10
packet[TCP].sport = 30

packet.show()


# to add payload to this packet, use the operator /
packet = packet/"GET HTTP/1.1\r\n\r\n"
packet.show()

# send packet
send(packet)
# packet[TCP].dport = (20, 30)
# [p for p in packet[TCP]]
# packet.show()
# send(IP(dst="192.168.1.9")/ICMP())