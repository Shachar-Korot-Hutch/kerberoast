# Based on the Kerberoast script from Tim Medin to extract the Kerberos tickets
# from a kirbi file.
# Modification to parse them into the JTR-format by Michael Kramer (SySS GmbH)
# Copyright [2015] [Tim Medin, Michael Kramer]
#
#Writen By Shachar (Hutch) Korot and omri inbar Based on Kirbi2john.py


from pyasn1.codec.ber import encoder, decoder
from multiprocessing import JoinableQueue, Manager
import glob

if __name__ == '__main__':
	import argparse

	parser = argparse.ArgumentParser(description='Read Mimikatz kerberos ticket then modify it and save it in crack_file')
	parser.add_argument('files', nargs='+', metavar='file.kirbi',
					help='File name to crack. Use asterisk \'*\' for many files.\n Files are exported with mimikatz or from extracttgsrepfrompcap.py')

	args = parser.parse_args()

	manager = Manager()
	enctickets = manager.list()

	i = 0
	for path in args.files:
		for f in glob.glob(path):
			with open(f, 'rb') as fd:
				data = fd.read()
			#data = open('f.read()

			if data[0] == '\x76':
				# rem dump
				enctickets.append((str(decoder.decode(data)[0][2][0][3][2]), i, f))
				i += 1
			elif data[:2] == '6d':
				for ticket in data.strip().split('\n'):
					enctickets.append((str(decoder.decode(ticket.decode('hex'))[0][4][3][2]), i, f))
					i += 1
	print "The Following Kirbi files will be Converted to Hashcat3.1+ Kerberos AS-REQ 23 type" + "\n"
	out=open("crack_file","r+")
	for et in enctickets:
		filename = et[2]
		tempsplit = filename
		tempsplit = tempsplit[tempsplit.find('~'):]
		tempsplit = tempsplit[1:]
		user = tempsplit[:tempsplit.find('.')]
		print user
		if not user:
			print filename + " is not by Mimikatz format! (), Guessing that the file name is match to the user name"
			user = filename[:filename.find('.kirbi')]
			out.write("$krb5tgs$23$*"+user+"$realm$test/spn*$"+et[0][:16].encode("hex")+"$"+et[0][16:].encode("hex")+"\n")
		else:
			out.write("$krb5tgs$23$*"+user+"$realm$test/spn*$"+et[0][:16].encode("hex")+"$"+et[0][16:].encode("hex")+"\n")
	out.close
	with open('crack_file', 'r') as hashes:
		print(hashes.read())


