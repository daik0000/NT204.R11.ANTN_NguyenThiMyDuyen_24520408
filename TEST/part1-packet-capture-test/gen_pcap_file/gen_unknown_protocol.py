from scapy.all import Ether, IP, ICMP, Raw, wrpcap

eth = Ether(src="aa:bb:cc:dd:ee:01", dst="aa:bb:cc:dd:ee:02")
ip = IP(src="192.168.1.100", dst="10.0.0.1")

# Layer 4: ICMP (Protocol 1). The pipeline should gracefully skip transport/app parsing.
icmp = ICMP(type=8, code=0)

# Raw Payload
payload = Raw(b"ping_payload_test")

packet = eth/ip/icmp/payload

wrpcap("TEST/part1-packet-capture-test/unknown_protocol/input.pcap", [packet])
print("Created TEST/part1-packet-capture-test/unknown_protocol/input.pcap")