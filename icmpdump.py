#!/usr/bin/env python3

from scapy.all import *
import os
import argparse

__description__ = 'Dump all ICMP data fields from a packet capture file.'
__author__ = 'straysheep-dev'
__version__ = '0.0.1'
__date__ = '2022/10/06'

"""
Source code put in public domain by straysheep-dev, no Copyright
https://github.com/straysheep-dev/parsing-utils
Use at your own risk

Description

ICMP packets have a variable length for the data field. This is how ICMP tunneling and data exfiltration is possible.
This script will take a packet capture file and dump all ICMP data fields as a bytearray into a single file.
From there you can use something like foremost, scalpel, or binwalk to extract data.


References

https://www.ietf.org/rfc/rfc792.txt
https://en.wikipedia.org/wiki/List_of_file_signatures
https://github.com/carlospolop/hacktricks/blob/master/forensics/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
"""

# Define arguments
parser = argparse.ArgumentParser(description="Dump all ICMP data fields from a packet capture file.")
parser.add_argument("-i", "--input", help="Path to a packet capture file to read, full or relative.", type=str, required=True)
parser.add_argument("-o", "--out", help="Data is written to the file OUT, full or relative path. If no OUT file is specified, data.bin is written to current directory.", type=str, required=False, default="data.bin")
args = parser.parse_args()

# Validate input file exists
if not os.path.isfile(args.input):
	print("[i]Input file not found.")
	exit()

# Apply the arguments to variables
pcap = rdpcap(args.input)

# Try to open and write the data file, raise exception if we can't
try:
	f = open(args.out, "wb")

except:
	print("[i]Error writing {}, be sure you have write permissions to the destination path.".format(args.out))
	exit()

# Define a function to loop through all ICMP data fields
# Write the data as a bytearray to a file
def icmp_dump():
	for i in pcap:
		if i.haslayer("ICMP"):
			f.write(bytearray(i[ICMP].load))

# Call the function
print("[>]Reading capture: {}...".format(args.input))
try:
	icmp_dump()
except:
	print("[i]Error reading file. Quitting.")

# Close the file
f.close()
print("[✓]Data written to: {}".format(args.out))
