#!/usr/bin/env python
from socket import inet_ntoa

class Information_Gathering:
	def __init__(self,arpfilename="/proc/net/arp", routefile="/proc/net/route"):
		self.arpfilename = arpfilename
		self.routefile = routefile

	def Parser(self):
		counter = 0
		ROUTE = []
		ARP = []
		for filename in [self.routefile, self.arpfilename]:
			f = open(filename, "r")
			for line in f.readlines():
				if counter == 0:
					pass
				elif counter == 1 and filename == self.routefile or counter == 2 and filename == self.routefile:
					ROUTE.append(line.split())
				elif counter > 2 and filename == self.routefile:
					break
				elif filename == self.arpfilename:
					ARP.append(line.split())
				else: 
					break
				counter += 1
			f.close()
			counter = 0
		return ROUTE,ARP

	def IFACE(self):
		try:
			return self.Parser()[0][0][0]
		except:
			pass

	def GATEWAY(self):
		try:
			RAW_GW = self.Parser()[0][0][2]
			GW_T = inet_ntoa(RAW_GW.decode("hex")).split(".")
			GW_T.reverse()
			GW = ".".join(GW_T)
		except:
			print "We couldn't recognize the GATEWAY, Check it out please"
			exit(1)
		return GW

	def GW_MAC(self):
		GW = self.GATEWAY()
		GW_MAC = ""
		ARP_T = self.Parser()[1]
		for entry in ARP_T:
			if GW in entry:
				GW_MAC = entry[3]
			else:
				pass
		return GW_MAC
	
	def NET_MASK(self):
		RAW_Value = self.Parser()[0][1][7]
		MASK_T = inet_ntoa(RAW_Value.decode("hex")).split(".")
		MASK_T.reverse()
		MASK = ".".join(MASK_T)
		return MASK
