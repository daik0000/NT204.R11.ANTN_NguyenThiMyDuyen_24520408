from scapy.all import Ether, IP, TCP, Raw, wrpcap

eth = Ether(src="aa:bb:cc:dd:ee:01", dst="aa:bb:cc:dd:ee:02")
ip = IP(src="192.168.1.100", dst="10.0.0.1")

tcp = TCP(sport=54321, dport=9999, flags="PA", seq=1001, ack=2001)

payload = Raw(b"Hello, this is a TCP payload for testing!")

packet = eth/ip/tcp/payload

wrpcap("TEST/part1-packet-capture-test/tcp_data/input.pcap", [packet])
print("Created TEST/part1-packet-capture-test/tcp_data/input.pcap")