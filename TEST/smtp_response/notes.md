# Test Case 10: SMTP response

## 1. Input
- Nguồn: `input.pcap` (sinh bằng Scapy, xem `gen_pcap_file/`)
- Nội dung: 1 gói TCP (flags `PA`) từ Server (10.0.0.1:25) về Client (192.168.1.100:12345), payload là 1 response multi-line (`250-`, `250-`, `250 `) - mô phỏng response EHLO liệt kê các extension.

## 2. Kết quả mong đợi 
- `status`: `"OK"`, không crash.
- `network_protocol`: `"IPv4"`, `src_ip`: `10.0.0.1`, `dst_ip`: `192.168.1.100`.
- `transport_protocol`: `"TCP"`, `src_port`: `25`, `dst_port`: `12345`, `transport_fields.flags`: `["PSH", "ACK"]`.
- `app_protocol`: `"SMTP"`, `detection_method`: `"port+payload"` (src_port=25 khớp `KNOWN_PORTS`, dòng đầu `250-` khớp `SMTP_RESP_RE`).
- `app_fields`:
  - `type`: `"response"`
  - `messages`:
    - `{"code": 250, "is_last_line": false, "message": "mail.example.com"}`
    - `{"code": 250, "is_last_line": false, "message": "PIPELINING"}`
    - `{"code": 250, "is_last_line": true, "message": "8BITMIME"}`
  - Lưu ý: chỉ dòng cuối cùng (`250 8BITMIME`, dùng khoảng trắng thay vì gạch ngang) có `is_last_line: true`.

## 3. Kết quả thực tế 
```json
"src_ip": "10.0.0.1",
  "dst_ip": "192.168.1.100",
  "network_protocol": "IPv4",
  "network_fields": {
    "ttl": 64,
    "header_length": 20,
    "ip_proto_number": 6
  },
  "src_port": 25,
  "dst_port": 12345,
  "transport_protocol": "TCP",
  "transport_fields": {
    "seq": 200,
    "ack": 100,
    "flags": [
      "PSH",
      "ACK"
    ],
    "window_size": 8192
  },
  "app_protocol": "SMTP",
  "detection_method": "port+payload",
  "app_fields": {
    "type": "response",
    "messages": [
      {
        "code": 250,
        "is_last_line": false,
        "message": "mail.example.com"
      },
      {
        "code": 250,
        "is_last_line": false,
        "message": "PIPELINING"
      },
      {
        "code": 250,
        "is_last_line": true,
        "message": "8BITMIME"
      }
    ]
  },
```

## 4. Kết luận
**PASS**