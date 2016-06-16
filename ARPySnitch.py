#!/usr/bin/env python
import threading
import socket
import struct
from netInfo import Information_Gathering
from mylocalip import getIP
try:
        from colorama import Fore as foreground
except:
        print "Install colorama module\npip install colorama"
from binascii import unhexlify, hexlify
opcodes = {"0002": "is-at", "0001":"who-has"}
Attacker = []

class ARPSniffer(threading.Thread):
	def __init__(self, GW_IP, GW_MAC):
		threading.Thread.__init__(self)
		self.GW_IP = GW_IP
		self.GW_MAC = GW_MAC
		self.arpsock = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.htons(0x0806))
#		self.arpsock.settimeout(0.1)
		try:
			self.arpdata = self.arpsock.recv(65535)
		except socket.timeout:
			pass

	def run(self):
		try:
			arp_header = struct.unpack('!2s2s1s1s2s6s4s6s4s', self.arpdata[14:42])
			if hexlify(arp_header[4]) == "0002" and hexlify(arp_header[5]) != self.GW_MAC.replace(":","") and socket.inet_ntoa(arp_header[6]) == self.GW_IP:
				try:
				   if hexlify(arp_header[5]) not in Attacker:
				   	Attacker.append(hexlify(arp_header[5]))
					print "="*50 
					print foreground.RED + "ARP Poison Detected" + foreground.RESET
					print "="*50 
					print "******************_ARP_HEADER_******************"
					print "Hardware Type: ", hexlify(arp_header[0])
					print "Protocol Type: ", hexlify(arp_header[1])
					print "Hardware Size: ", hexlify(arp_header[2])
					print "Protocol Size: ", hexlify(arp_header[3])
					print "Opcode: ", opcodes[hexlify(arp_header[4])]
					print "Attacker's MAC : ", foreground.RED + hexlify(arp_header[5]) + foreground.RESET
					print "Source IP : ", socket.inet_ntoa(arp_header[6])
					print "Destination MAC : ", hexlify(arp_header[7])
					print "Destination IP : ", socket.inet_ntoa(arp_header[8])
				   else:
					pass
				except:
					pass
		except:
				pass


def helper(GW_IP):
	try:
		from Ping_GW import PingGW
	except:
		print "Ping_GW: No Such Module"
		exit()
	PingGW(GW_IP)
	print "Pinging the GW"
def main():
	info = Information_Gathering()
	GW_IP = info.GATEWAY()
	GW_MAC = info.GW_MAC()
	IFACE = info.IFACE()
	if not GW_MAC:
		helper(GW_IP)
		from time import sleep
		del info
		sleep(1)
		inf = Information_Gathering()
		GW_MAC = inf.GW_MAC()
	print "GATEWAY IP:", GW_IP
	print "GATEWAY MAC:", GW_MAC
	while True:
	   try:
		IDS = ARPSniffer(GW_IP,GW_MAC)
		IDS.setDaemon(True)
		IDS.start()
	   except KeyboardInterrupt:
		break
if __name__ == "__main__":
	main()
