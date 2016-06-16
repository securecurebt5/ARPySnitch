#!/usr/bin/env python

from subprocess import check_output
from netInfo import Information_Gathering

info = Information_Gathering()
iface = info.IFACE() 

def getIP(iface=iface):
	ifconfig = check_output(["ifconfig", "%s"%iface])
	ip, mac = ifconfig.split()[6], ifconfig.split()[4]
	return ip.split(":")[1],  mac

