# Test Case 12: Malformed packet (no crash)

## 1. Input
- Nguồn: `input.pcap` (sinh bằng Scapy, xem `gen_pcap_file/`)
- Nội dung: 1 gói UDP từ Client (192.168.1.100:12345) đến Server (10.0.0.1:53), payload chỉ có 5 byte rác (`\x00\x01\x02\x03\x04`) - quá ngắn để là 1 DNS header hợp lệ (yêu cầu tối thiểu 12 byte).

## 2. Kết quả mong đợi 
**Lưu ý về cơ chế kích hoạt MALFORMED - cần hiểu đúng luồng xử lý:**
1. Tầng Network (IPv4) và Transport (UDP) parse thành công bình thường (`status` tạm thời vẫn `"OK"` ở 2 tầng này).
2. Detector: `detect_protocol_by_payload` bỏ qua nhánh DNS heuristic vì `len(payload) < 12` - trả `payload_proto="UNKNOWN"`. Nhưng `detect_protocol_by_port` khớp `dst_port=53` -> trả `port_proto="DNS"`. Vì payload-based là `UNKNOWN`, hệ thống dùng kết quả port-based -> `app_proto="DNS"`, **`detection_method="port"`** (không phải `"port+payload"` như 7 test case trước, vì payload không tự xác nhận được).
3. `parse_dns` được gọi với 5 byte này -> rớt vào check `len(raw_bytes) < 12` -> `raise ValueError(...)` -> `@safe_parse` bắt -> trả `status="MALFORMED"`.
4. Pipeline set `event_dict["status"] = "MALFORMED"` và gán `error_info`, nhưng **`app_protocol` vẫn giữ giá trị `"DNS"`** đã gán trước đó (pipeline không reset lại field này khi tầng application thất bại) - đây là hành vi đã biết, không phải bug, vì nó vẫn phản ánh đúng "detector đã xác định được đây khả năng là DNS qua port, chỉ là parse chi tiết thất bại".

Tổng kết Expected:
- `status`: `"MALFORMED"`.
- `network_protocol`: `"IPv4"`, `transport_protocol`: `"UDP"` - vẫn còn giá trị (giữ lại từ các tầng trước đã parse thành công, theo đúng nguyên tắc fall-through).
- `app_protocol`: `"DNS"`, `detection_method`: `"port"`.
- `error_info`: dict dạng `{"layer": "parse_dns", "detail": "Payload too short to be a valid DNS packet (5 bytes)."}`
- Quan trọng nhất: **chương trình không crash**
## 3. Kết quả thực tế 
Log khi đọc packet có hiện warning:
```
└─$ python main.py --pcap TEST/malformed_packet/input.pcap --output TEST/malformed_packet/events.jsonl 
2026-09-28 14:34:02,980 - INFO - Offline Mode: Reading PCAP file 'TEST/malformed_packet/input.pcap'
2026-09-28 14:34:02,981 - WARNING - Packet #1 MALFORMED: {'layer': 'parse_dns', 'detail': 'Payload too short to be a valid DNS packet (5 bytes).'}
2026-09-28 14:34:02,981 - INFO - System shutdown complete. Total packets processed: 1
```

```json
{
  "packet_id": 1,
  "timestamp": 1790580744.676033,
  "src_ip": "192.168.1.100",
  "dst_ip": "10.0.0.1",
  "network_protocol": "IPv4",
  "network_fields": {
    "ttl": 64,
    "header_length": 20,
    "ip_proto_number": 17
  },
  "src_port": 12345,
  "dst_port": 53,
  "transport_protocol": "UDP",
  "transport_fields": {
    "length": 13,
    "length_mismatch": false
  },
  "app_protocol": "DNS",
  "detection_method": "port",
  "app_fields": null,
  "raw_length": 47,
  "payload_length": 13,
  "status": "MALFORMED",
  "error_info": {
    "layer": "parse_dns",
    "detail": "Payload too short to be a valid DNS packet (5 bytes)."
  }
}
```

## 4. Kết luận
**PASS**