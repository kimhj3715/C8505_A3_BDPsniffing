# forged packet
from scapy.all import *

# global variables
a_input = []
user_input = []


mypacket = IP()
mypacket.src = "192.168.0.9"
mypacket.dst = "192.168.0.8"




user_input = raw_input("# ")

# encrypt the message first

for c in user_input:
	print c
	a_input.append(ord(c))




# create a forged packet with the data
for i in a_input:
	# put random values in IP and TCP header
	packet = fuzz(mypacket)/fuzz(UDP())
	# set destination port to 80 
	packet[UDP].dport = 80
	#packet[TCP].flag = 
	# manipulate "Type of Service" field of IP header
	packet.id = i
	print "[sent] ", str(unichr(i))
	# send packet
	packet.show()
	send(packet)

print a_input