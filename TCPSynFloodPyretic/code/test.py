from pyretic.lib.corelib import *
from pyretic.lib.std import *
from pyretic.lib.query import *


class printer(DynamicPolicy):
		
	def __init__ (self):
		super(printer,self).__init__(false)	
		q = packets()
		q.register_callback(self.addRule)
		self.policy = (match(srcip='10.0.0.1', dstip='10.0.0.2')  >> fwd(2)) + (match(srcip='10.0.0.2', dstip='10.0.0.1')  >> fwd(1))
	
	#def addRule(self, packet):
	#	self.policy = (match(srcip='10.0.0.1', dstip='10.0.0.2')  >> fwd(2)) + (match(srcip='10.0.0.2', dstip='10.0.0.1')  >> fwd(1))
	
def main():
	return (printer() + flood())
