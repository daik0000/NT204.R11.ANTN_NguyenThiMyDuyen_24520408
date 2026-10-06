from scapy.all import Ether, IP, TCP, Raw, wrpcap

eth = Ether(src="aa:bb:cc:dd:ee:01", dst="aa:bb:cc:dd:ee:02")
ip = IP(src="10.0.0.1", dst="192.168.1.100")

# Layer 4: TCP
tcp = TCP(sport=25, dport=12345, flags="PA", seq=200, ack=100)

# Raw Payload: SMTP server multi-line response
payload = Raw(b"250-mail.example.com\r\n250-PIPELINING\r\n250 8BITMIME\r\n")

packet = eth/ip/tcp/payload

wrpcap("TEST/part1-packet-capture-test/smtp_response/input.pcap", [packet])
print("Created TEST/part1-packet-capture-test/smtp_response/input.pcap")