from scapy.all import Ether, IP, TCP, Raw, wrpcap

eth = Ether(src="aa:bb:cc:dd:ee:01", dst="aa:bb:cc:dd:ee:02")
ip = IP(src="192.168.1.100", dst="10.0.0.1")

# Layer 4: TCP
tcp = TCP(sport=12345, dport=25, flags="PA", seq=100, ack=200)

# Raw Payload: SMTP client commands
payload = Raw(b"EHLO client.example.com\r\nMAIL FROM:\r\n")

packet = eth/ip/tcp/payload

wrpcap("TEST/smtp_command/input.pcap", [packet])
print("Created TEST/smtp_command/input.pcap")