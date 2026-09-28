# Test Case 09: SMTP command

## 1. Input
- Nguồn: `input.pcap` (sinh bằng Scapy, xem `gen_pcap_file/`)
- Nội dung: 1 gói TCP (flags `PA`) từ Client (192.168.1.100:12345) đến Server (10.0.0.1:25), payload gồm 2 lệnh SMTP pipelined: `EHLO client.example.com` và `MAIL FROM:` (không có tham số).

## 2. Kết quả mong đợi 
- `status`: `"OK"`, không crash.
- `network_protocol`: `"IPv4"`, `src_ip`: `192.168.1.100`, `dst_ip`: `10.0.0.1`.
- `transport_protocol`: `"TCP"`, `src_port`: `12345`, `dst_port`: `25`, `transport_fields.flags`: `["PSH", "ACK"]`.
- `app_protocol`: `"SMTP"`, `detection_method`: `"port+payload"` (dst_port=25 khớp `KNOWN_PORTS`, dòng đầu `EHLO ` cũng khớp `SMTP_COMMANDS`).
- `app_fields`:
  - `type`: `"command"`
  - `messages`: `[{"command": "EHLO", "arguments": "client.example.com"}, {"command": "MAIL FROM", "arguments": ""}]`
  - Lưu ý: `arguments` của lệnh thứ 2 là chuỗi rỗng `""`

## 3. Kết quả thực tế 
```json
  "src_ip": "192.168.1.100",
  "dst_ip": "10.0.0.1",
  "network_protocol": "IPv4",
  "network_fields": {
    "ttl": 64,
    "header_length": 20,
    "ip_proto_number": 6
  },
  "src_port": 12345,
  "dst_port": 25,
  "transport_protocol": "TCP",
  "transport_fields": {
    "seq": 100,
    "ack": 200,
    "flags": [
      "PSH",
      "ACK"
    ],
    "window_size": 8192
  },
  "app_protocol": "SMTP",
  "detection_method": "port+payload",
  "app_fields": {
    "type": "command",
    "messages": [
      {
        "command": "EHLO",
        "arguments": "client.example.com"
      },
      {
        "command": "MAIL FROM",
        "arguments": ""
      }
    ]
  },
```

## 4. Kết luận
**PASS**