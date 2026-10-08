from scapy.all import Ether, IP, TCP, wrpcap

eth = Ether(src="aa:bb:cc:dd:ee:01", dst="aa:bb:cc:dd:ee:02")
ip = IP(src="192.168.1.100", dst="10.0.0.1")

# S (SYN), SA (SYN-ACK), A (ACK)
syn = TCP(sport=12345, dport=80, flags="S", seq=1000)
syn_ack = TCP(sport=80, dport=12345, flags="SA", seq=2000, ack=1001)
ack = TCP(sport=12345, dport=80, flags="A", seq=1001, ack=2001)

wrpcap("TEST/part1-packet-capture-test/tcp_handshake/input.pcap", [eth/ip/syn, eth/ip/syn_ack, eth/ip/ack])
print("Created TEST/part1-packet-capture-test/tcp_handshake/input.pcap")