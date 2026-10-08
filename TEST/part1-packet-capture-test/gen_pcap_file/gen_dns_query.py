from scapy.all import Ether, IP, UDP, DNS, DNSQR, wrpcap

eth = Ether(src="aa:bb:cc:dd:ee:01", dst="aa:bb:cc:dd:ee:02")
ip = IP(src="192.168.1.100", dst="10.0.0.1")

# Layer 4: UDP
udp = UDP(sport=12345, dport=53)

# Layer 7: DNS query (Scapy automatically handles structure and compression pointers)
dns = DNS(id=0x1234, qr=0, qdcount=1, qd=DNSQR(qname="example.com", qtype=1))

packet = eth/ip/udp/dns

wrpcap("TEST/part1-packet-capture-test/dns_query/input.pcap", [packet])
print("Created TEST/part1-packet-capture-test/dns_query/input.pcap")