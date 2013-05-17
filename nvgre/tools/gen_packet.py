from scapy.all import *

class NVGRE(Packet):
	name = "NVGRE"
	fields_desc = [ ShortField("flags", 4),
			ShortField("proto", 1),
			ShortField("checksum", 0),
			ShortField("reserved", 0),
			IntField("key", 0)]

ether_outer = Ether(dst="aa:bb:cc:dd:ee:ff")
ip_outer = IP(src = "10.1.1.1", dst = "10.1.1.2")
nvgre = GRE()
ether_in = Ether()
ip_in = IP(dst = "10.10.1.1")

nvgre.key_present = 1
nvgre.key = 10 << 8
nvgre.proto = 0x6558
nvgre.version = 2

p = ip_outer / nvgre / ether_in / ip_in / ICMP()
#p = ip_outer / UDP(dport = 80) / ("X"*10)

#send(IP(dst="10.0.0.2") / UDP(dport = 80) / ("X" * 10))
send(p)
