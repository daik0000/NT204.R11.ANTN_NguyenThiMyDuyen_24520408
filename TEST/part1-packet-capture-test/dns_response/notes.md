# Test Case 08: DNS Response

## 1. Input
- Nguồn: `input.pcap` (sinh bằng Scapy, xem `gen_pcap_file/`)
- Nội dung: 1 gói UDP từ Server (10.0.0.1:53) về Client (192.168.1.100:12345), payload là 1 DNS response cho `example.com`, `rcode=0`, kèm 1 answer record kiểu A trỏ tới `93.184.216.34`.

## 2. Kết quả mong đợi 
- `status`: `"OK"`, không crash.
- `network_protocol`: `"IPv4"`, `src_ip`: `10.0.0.1`, `dst_ip`: `192.168.1.100`.
- `transport_protocol`: `"UDP"`, `src_port`: `53`, `dst_port`: `12345`.
- `app_protocol`: `"DNS"`, `detection_method`: `"port+payload"`.
- `app_fields`:
  - `transaction_id`: `4660`
  - `type`: `"response"`
  - `rcode`: `0`
  - `queries`: `[{"name": "example.com", "qtype": "A"}]`
  - `answers`: `[{"name": "example.com", "type": "A", "data": "93.184.216.34"}]`

## 3. Kết quả thực tế 
```json
"src_ip": "10.0.0.1",
  "dst_ip": "192.168.1.100",
  "network_protocol": "IPv4",
  "network_fields": {
    "ttl": 64,
    "header_length": 20,
    "ip_proto_number": 17
  },
  "src_port": 53,
  "dst_port": 12345,
  "transport_protocol": "UDP",
  "transport_fields": {
    "length": 64,
    "length_mismatch": false
  },
  "app_protocol": "DNS",
  "detection_method": "port+payload",
  "app_fields": {
    "transaction_id": 4660,
    "type": "response",
    "rcode": 0,
    "queries": [
      {
        "name": "example.com",
        "qtype": "A"
      }
    ],
    "answers": [
      {
        "name": "example.com",
        "type": "A",
        "data": "93.184.216.34"
      }
    ]
```

## 4. Kết luận
**PASS**