from scapy.all import Ether, IP, TCP, Raw, wrpcap

eth = Ether(src="aa:bb:cc:dd:ee:01", dst="aa:bb:cc:dd:ee:02")
ip = IP(src="192.168.1.100", dst="10.0.0.1")

# Layer 4: TCP
tcp = TCP(sport=12345, dport=80, flags="PA", seq=100, ack=200)

# Raw Payload: HTTP POST request with body
payload = Raw(b"POST /api/login HTTP/1.1\r\nHost: example.com\r\nContent-Length: 27\r\n\r\nusername=admin&password=123")

packet = eth/ip/tcp/payload

wrpcap("TEST/http_post/input.pcap", [packet])
print("Created TEST/http_post/input.pcap")