# Test Case 11: Unknown protocol (no crash)

## 1. Input
- Nguồn: `input.pcap` (sinh bằng Scapy, xem `gen_pcap_file/`)
- Nội dung: 1 gói ICMP (type=8/Echo Request, IANA protocol number = 1) từ Client (192.168.1.100) đến Server (10.0.0.1), có kèm payload giả lập.

## 2. Kết quả mong đợi 
ICMP vẫn là giao thức hợp lệ ở tầng IPv4 (`parse_ipv4` parse thành công bình thường), chỉ là hệ thống **không hỗ trợ parse tầng Transport/Application cho ICMP** (bảng `IP_PROTO_TO_NAME` trong `pipeline.py` chỉ map protocol number 6/TCP và 17/UDP). Vì vậy kết quả mong đợi hiện tại là:

- `status`: `"OK"` - **không phải** `"UNKNOWN"` (giá trị `"UNKNOWN"` chỉ dành cho packet không phải IPv4 ở tầng Network, ví dụ ARP/IPv6 - ICMP vẫn là IPv4 hợp lệ).
- `network_protocol`: `"IPv4"`, `src_ip`: `192.168.1.100`, `dst_ip`: `10.0.0.1`, `network_fields.ip_proto_number`: `1`.
- `transport_protocol`: `null`, `transport_fields`: `null` (vì protocol number 1 không có trong `IP_PROTO_TO_NAME`, pipeline dừng lại ngay sau tầng Network).
- `app_protocol`: `null`, `detection_method`: `null`.

## 3. Kết quả thực tế 
```json
{
  "src_ip": "192.168.1.100",
  "dst_ip": "10.0.0.1",
  "network_protocol": "IPv4",
  "network_fields": {
    "ttl": 64,
    "header_length": 20,
    "ip_proto_number": 1
  },
  "src_port": null,
  "dst_port": null,
  "transport_protocol": null,
  "transport_fields": null,
  "app_protocol": null,
  "detection_method": null,
  "app_fields": null,
  "raw_length": 59,
  "payload_length": 25,
  "status": "OK",
}
```

## 4. Kết luận
**PASS**