# Test Case 01: TCP Handshake

## 1. Input
- Nguồn: File `input.pcap` (sinh bằng thư viện Scapy).
- Nội dung: 3 gói tin Ether/IPv4/TCP mô phỏng quá trình thiết lập kết nối (3-way handshake) giữa Client (192.168.1.100:12345) và Server (10.0.0.1:80). Không có Application data.

## 2. Kết quả mong đợi
- Hệ thống xử lý đủ 3 gói tin, không crash.
- Mọi gói tin đều có `status: "OK"`.
- `network_protocol`: "IPv4".
- `transport_protocol`: "TCP".
- `payload_length`: ~20 (Chỉ chứa độ dài TCP header trần, không có option, không có application data).
- `app_protocol`: `null` (None) - do app_payload rỗng nên tầng Detector không được gọi.
- `transport_fields.flags` ghi nhận thứ tự cờ chính xác: 
  - Gói 1: `["SYN"]`
  - Gói 2: `["SYN", "ACK"]` (Theo chuẩn hiển thị "SA" của Scapy)
  - Gói 3: `["ACK"]`

## 3. Kết quả thực tế 
(So sánh với file events.jsonl trong cùng thư mục: Hệ thống đã parse đúng toàn bộ các cờ TCP, payload_length ghi nhận đúng là 20, và app_protocol là null đúng như kỳ vọng.)

## 4. Kết luận
**PASS**