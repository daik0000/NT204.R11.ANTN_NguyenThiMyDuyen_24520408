# Test Case 05: HTTP POST with body

## 1. Input
- Nguồn: `input.pcap` (sinh bằng Scapy, xem `gen_pcap_file/`)
- Nội dung: 1 gói TCP (flags `PA`) từ Client (192.168.1.100:12345) đến Server (10.0.0.1:80), payload là 1 HTTP POST request có `Content-Length: 27` và body `username=admin&password=123` (đúng 27 byte, khớp chính xác với Content-Length khai báo).

## 2. Kết quả mong đợi
- `status`: `"OK"`, không crash.
- `network_protocol`: `"IPv4"`, `src_ip`: `192.168.1.100`, `dst_ip`: `10.0.0.1`.
- `transport_protocol`: `"TCP"`, `src_port`: `12345`, `dst_port`: `80`, `transport_fields.flags`: `["PSH", "ACK"]`.
- `app_protocol`: `"HTTP"`, `detection_method`: `"port+payload"`.
- `app_fields`:
  - `type`: `"request"`
  - `method`: `"POST"`
  - `path`: `"/api/login"`
  - `version`: `"HTTP/1.1"`
  - `headers`: `{"Host": "example.com", "Content-Length": "27"}`
  - `body_preview`: `"username=admin&password=123"` (đúng 27 ký tự, không bị cắt vì dưới ngưỡng 1024).

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
  "dst_port": 80,
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
  "app_protocol": "HTTP",
  "detection_method": "port+payload",
  "app_fields": {
    "headers": {
      "Host": "example.com",
      "Content-Length": "27"
    },
    "type": "request",
    "method": "POST",
    "path": "/api/login",
    "version": "HTTP/1.1",
    "body_preview": "username=admin&password=123"
  },
```

## 4. Kết luận
**PASS**