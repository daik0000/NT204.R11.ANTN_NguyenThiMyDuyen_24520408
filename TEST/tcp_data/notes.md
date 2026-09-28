# Test Case 02: TCP Data with Payload

## 1. Input
- Nguồn: File `input.pcap` (sinh bằng Scapy).
- Nội dung: 1 gói tin Ether/IPv4/TCP. Điểm khác biệt là có chứa Raw Payload dài 41 bytes (`"Hello, this is a TCP payload for testing!"`).
- Port đích: 9999 (Non-standard port, không thuộc quy tắc nhận diện của ứng dụng).

## 2. Kết quả mong đợi 
- Hệ thống xử lý không lỗi, không crash.
- `status`: "OK" (Yêu cầu `unknown_policy` trong file `settings.yaml` đang đặt là `log`).
- `network_protocol`: "IPv4".
- `transport_protocol`: "TCP".
- `payload_length`: 61 (20 bytes TCP header + 41 bytes application data).
- `app_protocol`: "UNKNOWN" (Vì không khớp port và payload signature).
- `transport_fields.flags`: `["PSH", "ACK"]` (Chữ "PA" theo chuẩn Scapy).

## 3. Kết quả thực tế 
(So sánh `events.jsonl`: Kiểm chứng trường `payload_length` trả về đúng 61 và `app_protocol` là "UNKNOWN").

## 4. Kết luận
**PASS**