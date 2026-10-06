from scapy.all import Ether, IP, UDP, DNS, DNSQR, DNSRR, wrpcap

eth = Ether(src="aa:bb:cc:dd:ee:01", dst="aa:bb:cc:dd:ee:02")
ip = IP(src="10.0.0.1", dst="192.168.1.100")

# Layer 4: UDP
udp = UDP(sport=53, dport=12345)

# Layer 7: DNS response with 1 answer
dns = DNS(id=0x1234, qr=1, aa=1, rcode=0, qdcount=1, ancount=1,
          qd=DNSQR(qname="example.com", qtype=1),
          an=DNSRR(rrname="example.com", type=1, rdata="93.184.216.34"))

packet = eth/ip/udp/dns

wrpcap("TEST/part1-packet-capture-test/dns_response/input.pcap", [packet])
print("Created TEST/part1-packet-capture-test/dns_response/input.pcap")