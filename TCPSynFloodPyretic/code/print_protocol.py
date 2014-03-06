from pyretic.lib.corelib import *
from pyretic.lib.std import *

SYN_rec = {}

def printer(packet):
	print "----------------------------"
	print packet
	print packet['ethtype']	
	
	if packet['protocol'] == 0x06:
		print "IP Protocol: TCP"
		
	
	elif packet['protocol'] == 0x11:
		print "IP Protocol: UDP"
	
	elif packet['protocol'] == 0x01:
		print "IP Protocol: ICMP"
		print packet['switch']
		SYN_rec[packet['srcmac']] = packet['dstmac']
		
	else :
		print "NOTHING"
	
	print SYN_rec
	

def dpi():
  q = packets()
  q.register_callback(printer)
  return q

def main():

	return dpi()
