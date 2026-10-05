# Test Case 06: HTTP response (status code + header)

## 1. Input
- Nguồn: `input.pcap` (sinh bằng Scapy, xem `gen_pcap_file/`)
- Nội dung: 1 gói TCP (flags `PA`) từ Server (10.0.0.1:80) về Client (192.168.1.100:12345), payload là 1 HTTP response `200 OK` kèm header `Server`, `Content-Length: 13` và body `Hello, World!` (đúng 13 byte).

## 2. Kết quả mong đợi
- `status`: `"OK"`, không crash.
- `network_protocol`: `"IPv4"`, `src_ip`: `10.0.0.1`, `dst_ip`: `192.168.1.100`.
- `transport_protocol`: `"TCP"`, `src_port`: `80`, `dst_port`: `12345`, `transport_fields.flags`: `["PSH", "ACK"]`.
- `app_protocol`: `"HTTP"`, `detection_method`: `"port+payload"` (src_port=80 khớp `KNOWN_PORTS`, payload cũng khớp signature `HTTP/1.` ở start line).
- `app_fields`:
  - `type`: `"response"`
  - `version`: `"HTTP/1.1"`
  - `status_code`: `200` 
  - `reason`: `"OK"`
  - `headers`: `{"Server": "nginx", "Content-Length": "13"}`
  - `body_preview`: `"Hello, World!"`

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
  "src_port": 80,
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
  "app_protocol": "HTTP",
  "detection_method": "port+payload",
  "app_fields": {
    "headers": {
      "Server": "nginx",
      "Content-Length": "13"
    },
    "type": "response",
    "version": "HTTP/1.1",
    "status_code": 200,
    "reason": "OK",
    "body_preview": "Hello, World!"
  },
  "raw_length": 121,
  "payload_length": 87,
  "status": "OK",
```

## 4. Kết luận
**PASS**