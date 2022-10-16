from scapy.all import *

ip = 'scanme.nmap.org'

def ARPPing(ip):
	ans, unans = srp(Ether(dst='ff:ff:ff:ff:ff:ff')/ARP(pdst=ip), timeout = 3)
	ans.summary(lambda query, answer: answer.sprintf("%s : %s" %(answer[ARP].psrc, answer[ARP].hwsrc)))

def ICMPechoPing(ip):
	pkt = IP(dst=ip)/ICMP(type = 8) #type echo = 8, reply echo = 0
	ans, unans = sr(pkt, timeout=1)
	ans.summary(lambda query, answer: answer.sprintf("Host %s is up" %answer[IP].src))

def ICMPTimestampPing(ip):
	pkt = IP(dst=ip) / ICMP(type = 13) #type echo = 13, reply = 14
	ans, unans = sr(pkt, timeout=1)
	ans.summary(lambda query, answer: answer.sprintf("Host %s is up" % answer[IP].src))

def ICMPMaskRequest(ip):
	pkt = IP(dst=ip) / ICMP(type=17)  # type echo = 17, reply = 18
	ans, unans = sr(pkt, timeout=1)
	ans.summary(lambda query, answer: answer.sprintf("Host %s is up" % answer[IP].src))

def SYNPing(ip):
	ans, unans = sr(IP(dst = ip)/TCP(dport = 80, flags = 'S', seq = RandShort()), timeout = 1)
	for query, answer in ans:
		print("Host %s is up" %answer[IP].src)
		print(answer.summary())
		if answer[TCP].flags == 'SA':
			send(IP(dst=answer[IP].src)/TCP(dport=80, flags = 'R', seq = answer[TCP].ack),  verbose = 0)

def ACKPing(ip):
	ans, unans = sr(IP(dst=ip) / TCP(dport=80, flags='A', seq=RandShort()), timeout=1)
	for query, answer in ans:
		if answer[TCP].flags == 'R':
			print("Host %s is up" %answer[IP].src)

def UDPPing(ip):
    ans, unans = sr(IP(dst = ip)/UDP(), timeout = 1)
    unans.summary(lambda query: query.sprintf("Host %s is up" %query[IP].dst))

def TCPConnectScan(ip):
	ans, unans = sr(IP(dst = ip)/TCP(sport = RandShort(),dport = ports, flags = 'S', seq = RandInt()), timeout = 10, verbose = 0)
	for query, answer in ans:
		if answer[TCP].flags == 'SA':
			print(answer.summary())
			print("%s : Ports open: %s" %(query[IP].dst, query[TCP].dport))
			send(IP(dst=answer[IP].src)/TCP(dport=answer[TCP].sport, flags='A',seq=answer[TCP].ack, ack=answer[TCP].seq+1), verbose = 1)
			send(IP(dst=answer[IP].src)/TCP(dport=answer[TCP].sport, flags='RA', seq=answer[TCP].ack,
                                              ack=answer[TCP].seq + 1), verbose = 0)

def TCPSYNScan(ip):
	ans, unans = sr(IP(dst=ip)/TCP(sport = RandShort(),dport = ports, flags = 'S', seq = RandInt()), timeout = 10, verbose = 0)
	for query, answer in ans:
		if answer[TCP].flags == 'SA':
			print(answer.summary())
			print("%s : Port open: %s" % (query[IP].dst, query[TCP].dport))
			send(IP(dst=answer[IP].src) / TCP(dport=answer[TCP].sport, flags='R', seq=answer[TCP].ack, ack=answer[TCP].seq + 1), verbose = 0)

def UDPScan(ip):
	ans, unans = sr(IP(dst=ip)/UDP(dport=ports), timeout = 1)
	for query in unans:
		print(query.summary())
		print("%s: Port open: %s" % (query[IP].dst, query[UDP].dport))

def NULLScan(ip):
	ans, unans = sr(IP(dst=ip)/TCP(sport=RandShort(), dport=ports, flags = '', seq=RandInt()), timeout=1)
	print("%d ports open|filtered" %unans.__len__())
	for query, answer in ans:
		if answer[TCP].flags == 'RA':
			print("Port %d is close" %answer[TCP].sport)

def FINScan(ip):
	ans, unans = sr(IP(dst=ip) / TCP(sport=RandShort(), dport=ports, flags = 'F', seq=RandInt()), timeout=1)
	print("%d ports open|filtered" % unans.__len__())
	for query, answer in ans:
		if answer[TCP].flags == 'RA':
			print("Port %d is close" % answer[TCP].sport)

def XmasScan(ip):
	ans, unans = sr(IP(dst=ip) / TCP(sport=RandShort(), dport=ports, flags='FPU', seq=RandInt()), timeout=10)
	print("%d ports open|filtered" % unans.__len__())
	for query, answer in ans:
		if answer[TCP].flags == 'RA':
        	print("Port %d is close" % answer[TCP].sport)

def ACKScan(ip):
	ans, unans = sr(IP(dst=ip) / TCP(sport=RandShort(), dport=ports, flags='A', seq=RandInt()), timeout=10)
	for query, answer in ans:
		if answer[TCP].flags == 'R':
			print("Port %d is unfiltered" % answer[TCP].sport)

def CustomScan(ip):
	flag = 'UAPRSF'
	ans, unans = sr(IP(dst=ip) / TCP(sport=RandShort(), dport=ports, flags=flag, seq=RandInt()), timeout=10)
	for query, answer in ans:
    	print(answer)

