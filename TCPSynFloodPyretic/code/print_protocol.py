
from pyretic.lib.corelib import *
from pyretic.lib.std import *

from struct import *

SYN_rec = []
SYNACK_rec = []
FRIENDLY_hosts = []

TCP_PROTO = 0x06
IMP_PROTO = 0x11
UDP_PROTO = 0x01

SYN_FLAG = 0x002
SYNACK_TCP_FLAG = 0x012
ACKCON_FLAG = 0x010
FIN_FLAG = 0X001

def printer(packet):
	print "-----------------------------------------------"
	#print packet
	#print packet['ethtype']
	
	print "Ethernet packet, try to decode"
	raw_bytes = [ord(c) for c in packet['raw']]
	#print "ethernet payload is %d" % packet['payload_len']
	
	eth_payload_bytes = raw_bytes[packet['header_len']:]
	ip_header_len = (eth_payload_bytes[0] & 0b00001111) * 4
	ip_payload_bytes = eth_payload_bytes[ip_header_len:]

	if packet['protocol'] == TCP_PROTO:
		print "TCP PACKET Receive"
		
		tcp_flag = ip_payload_bytes[13]
		
		if tcp_flag == SYN_FLAG :
			
			print "SYN Receive"
			print "From IP: %s (MAC: %s)  ------->  To IP: %s (MAC: %s)" % (packet['srcip'],packet['srcmac'],packet['dstip'],packet['dstmac'])
			
			if packet['srcip'] not in SYN_rec :
				SYN_rec.remove(packet['srcip'])

		elif tcp_flag == SYNACK_TCP_FLAG :
			
			print "SYN-ACK Receive"
			print "From IP: %s (MAC: %s)  ------->  To IP: %s (MAC: %s)" % (packet['srcip'],packet['srcmac'],packet['dstmac'],packet['dstmac'])
			
			if packet['dstip'] in SYN_rec :
				SYNACK_rec.append(packet['dstip'])
				SYN_rec.remove(packet['dstip'])
				

		
		elif tcp_flag == ACKCON_FLAG :
			print "ACK Receive"
			print "From IP: %s (MAC: %s)  ------->  To IP: %s (MAC: %s)" % (packet['srcip'],packet['srcmac'],packet['dstmac'],packet['dstmac'])			
			if packet['srcip'] in SYN_rec :
				FRIENDLY_hosts.append(packet['dstip'])
				SYNACK_rec.remove(packet['dstip'])
				
				#INSTALL RULE TABLES
		
		elif tcp_flag == FIN_FLAG :
			print "FIN Receive"
			print "From IP: %s (MAC: %s)  ------->  To IP: %s (MAC: %s)" % (packet['srcip'],packet['srcmac'],packet['dstmac'],packet['dstmac'])
			
		print "SYN List"
		print SYN_rec
	
		print "SYN ACK List"
		print SYNACK_rec
	
		print "ACK List"
		print FRIENDLY_hosts					
				
		
	elif packet['protocol'] == 0x11:
		print "UDP packet Receive"
	
	elif packet['protocol'] == 0x01:
		print "ICMP packet Receive"
		print packet['switch']
		
	else :
		print "NOTHING"
	
	
	print "-----------------------------------------------"

def dpi():
  q = packets()
  q.register_callback(printer)
  return q

def main():

	return (dpi() + flood())
