from scapy.all import Ether, IP, TCP, Raw, wrpcap

eth = Ether(src="aa:bb:cc:dd:ee:01", dst="aa:bb:cc:dd:ee:02")
ip = IP(src="10.0.0.1", dst="192.168.1.100")

# Layer 4: TCP
tcp = TCP(sport=80, dport=12345, flags="PA", seq=200, ack=100)

# Raw Payload: HTTP response
payload = Raw(b"HTTP/1.1 200 OK\r\nServer: nginx\r\nContent-Length: 13\r\n\r\nHello, World!")

packet = eth/ip/tcp/payload

wrpcap("TEST/part1-packet-capture-test/http_response/input.pcap", [packet])
print("Created TEST/part1-packet-capture-test/http_response/input.pcap")