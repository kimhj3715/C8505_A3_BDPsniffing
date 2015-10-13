# main.py
from encrypt import *
import argparse
import sys

def parse_arguments():
	parser = argparse.ArgumentParser()
	group = parser.add_mutually_exclusive_group()
	group.add_argument("-e", "--encrypt", action="store")
	group.add_argument("-d", "--decrypt", action="store")
	return parser.parse_args()


def main():
	args = parse_arguments()
	if(args.encrypt is not None):
		user_input = args.encrypt 	# give from terminal
		pwd = raw_input("Give me a password: ")
		enc_text = encrypt(user_input, pwd)
		print "encrypting..."
		print enc_text

		# open a file and write encrypted text
		f = open("text", "w")
		f.write(enc_text)

	elif(args.decrypt is not None):
		enc_text = ""
		pwd = raw_input("Give me a password: ")

		# open file and extract the original text
		with open('text') as fo:
			for e in fo:
				enc_text += e


		result = decrypt(enc_text, pwd)
		print "decrypting..."
		print result
	else:
		exit("An unexpected error has occured. Please check your arguments.")

if __name__ == '__main__':
	try:
		main()
	except KeyboardInterrupt:
		print("Terminate signal received. Exiting...")