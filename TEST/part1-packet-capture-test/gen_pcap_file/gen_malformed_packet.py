from scapy.all import Ether, IP, UDP, Raw, wrpcap

eth = Ether(src="aa:bb:cc:dd:ee:01", dst="aa:bb:cc:dd:ee:02")
ip = IP(src="192.168.1.100", dst="10.0.0.1")

# Layer 4: UDP to port 53 (DNS)
udp = UDP(sport=12345, dport=53)

# Raw Payload: garbage bytes, too short for a valid DNS header
# This will trigger _looks_like_dns_header validation -> MALFORMED status.
payload = Raw(b"\x00\x01\x02\x03\x04")

packet = eth/ip/udp/payload

wrpcap("TEST/malformed_packet/input.pcap", [packet])
print("Created TEST/malformed_packet/input.pcap")