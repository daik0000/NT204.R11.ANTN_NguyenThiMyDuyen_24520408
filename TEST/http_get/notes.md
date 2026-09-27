# Test Case 04: HTTP GET

## 1. Input
- Nguồn: `input.pcap` (sinh bằng Scapy, xem `gen_pcap_file/gen_test_cases.py`)
- Nội dung: 1 gói TCP (flags `PA`) từ Client (192.168.1.100:12345) đến Server (10.0.0.1:80), payload là 1 HTTP GET request đầy đủ header, không có body.

## 2. Kết quả mong đợi 
- `status`: `"OK"`, không crash.
- `network_protocol`: `"IPv4"`, `src_ip`: `192.168.1.100`, `dst_ip`: `10.0.0.1`, `network_fields.ttl`: `64` (mặc định Scapy — đối chiếu lại Actual để chắc chắn).
- `transport_protocol`: `"TCP"`, `src_port`: `12345`, `dst_port`: `80`, `transport_fields.flags`: `["PSH", "ACK"]`.
- `app_protocol`: `"HTTP"`, `detection_method`: `"port+payload"` (dst_port=80 khớp `KNOWN_PORTS` **và** payload khớp signature `GET ` - cả 2 phương pháp đồng thuận).
- `app_fields`:
  - `type`: `"request"`
  - `method`: `"GET"`
  - `path`: `"/index.html"`
  - `version`: `"HTTP/1.1"`
  - `headers`: `{"Host": "example.com", "Accept": "*/*"}`
  - Không có key `body_preview` (vì không có body - payload kết thúc ngay sau `\r\n\r\n`).

## 3. Kết quả thực tế 
``` json
  "src_ip": "192.168.1.100",
  "dst_ip": "10.0.0.1",
  "network_protocol": "IPv4",
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
  },
  "app_protocol": "HTTP",
  "detection_method": "port+payload",
  "app_fields": {
    "headers": {
      "Host": "example.com",
      "Accept": "*/*"
    },
    "type": "request",
    "method": "GET",
    "path": "/index.html",
    "version": "HTTP/1.1"
  },
  "status": "OK"
```
## 4. Kết luận
**PASS**