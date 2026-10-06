from scapy.all import Ether, IP, TCP, Raw, wrpcap

eth = Ether(src="aa:bb:cc:dd:ee:01", dst="aa:bb:cc:dd:ee:02")
ip = IP(src="192.168.1.100", dst="10.0.0.1")

# Layer 4: TCP
tcp = TCP(sport=12345, dport=80, flags="PA", seq=100, ack=200)

# Raw Payload: HTTP GET request
payload = Raw(b"GET /index.html HTTP/1.1\r\nHost: example.com\r\nAccept: */*\r\n\r\n")

packet = eth/ip/tcp/payload

wrpcap("TEST/part1-packet-capture-test/http_get/input.pcap", [packet])
print("Created TEST/part1-packet-capture-test/http_get/input.pcap")