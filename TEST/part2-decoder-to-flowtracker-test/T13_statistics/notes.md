# T13 – Statistics

## Input
`input.pcap`, 9 gói của một kết nối TCP 10.0.0.1:40601 → 10.0.0.2:9000, gói i gửi lúc T + (i − 1):
handshake (3 gói), 4 gói dữ liệu hai chiều có kích thước đã biết, rồi FIN/ACK hai chiều.

## Bảng tính tay từng gói
Frame = 14 (Ethernet) + 20 (IP) + 20 (TCP) + dữ liệu ứng dụng.

| # | t | Hướng | Flags | Dữ liệu | Frame | flow_state |
|---|---|---|---|---|---|---|
| 1 | 0 | F | SYN | 0 | 54 | HANDSHAKE |
| 2 | 1 | B | SYN,ACK | 0 | 54 | HANDSHAKE |
| 3 | 2 | F | ACK | 0 | 54 | ESTABLISHED |
| 4 | 3 | F | PSH,ACK | 10 | 64 | ESTABLISHED |
| 5 | 4 | B | PSH,ACK | 20 | 74 | ESTABLISHED |
| 6 | 5 | F | PSH,ACK | 30 | 84 | ESTABLISHED |
| 7 | 6 | B | PSH,ACK | 40 | 94 | ESTABLISHED |
| 8 | 7 | F | FIN,ACK | 0 | 54 | CLOSING |
| 9 | 8 | B | FIN,ACK | 0 | 54 | CLOSED |

## Kết quả mong đợi (tính tay)
| Bộ đếm | Cách tính | Giá trị |
|---|---|---|
| packet_count | 9 gói | 9 |
| fwd / bwd packet | F: 1,3,4,6,8; B: 2,5,7,9 | 5 / 4 |
| byte_count | 54×5 + 64 + 74 + 84 + 94 | 586 |
| fwd_byte_count | 54 + 54 + 64 + 84 + 54 | 310 |
| bwd_byte_count | 54 + 74 + 94 + 54 | 276 |
| payload_byte_count | 10 + 20 + 30 + 40 (ACK/handshake/FIN đóng góp 0) | 100 |
| syn_count | gói 1, 2 | 2 |
| ack_count | gói 2 → 9 | 8 |
| fin_count | gói 8, 9 | 2 |
| rst_count | không có | 0 |
| duration | 1700000008 − 1700000000 | 8.0 |
| state / close_reason | thấy đủ FIN hai chiều | CLOSED / tcp_closed |

Lưu ý: `payload_length` của event = 20 + dữ liệu (30, 40, 50, 60 cho gói 4–7), khác `payload_byte_count` của flow.

## Kết quả thực tế
- `events.jsonl`: 9 event, tất cả `status=OK`, `preprocess_status=valid`, `processing_action=defaults_filled`.
  `raw_length` = 54, 54, 54, 64, 74, 84, 94, 54, 54; `payload_length` = 20, 20, 20, 30, 40, 50, 60, 20, 20.
  `direction` F,B,F,F,B,F,B,F,B; `flow_state` HANDSHAKE, HANDSHAKE, ESTABLISHED ×5, CLOSING, CLOSED.
  Bốn gói dữ liệu (4–7) có `app_protocol=UNKNOWN`, các gói còn lại `null`.
- `flows.jsonl`: 1 flow (54ecea0fe1a0ba2b): packet 9 (5/4), byte 586 (310/276), payload 100,
  syn 2, ack 8, fin 2, rst 0, start 1700000000.0, last_seen 1700000008.0, duration 8.0,
  state=CLOSED, close_reason=tcp_closed, midstream=false, application_protocol=UNKNOWN.

## Kết luận
**PASS**
- `payload_byte_count = 100 = 10+20+30+40`: chỉ tính dữ liệu ứng dụng, handshake/ACK/FIN đóng góp 0;
  khác tổng `payload_length` của event (440), vì `payload_length` gồm cả 20 byte TCP header.
- SYN/ACK tăng cả `syn_count` và `ack_count` (đúng định nghĩa mỗi bộ đếm = số gói *mang cờ đó*),
  nên `ack_count = 8` (gói 2 → 9) còn `syn_count = 2`.
- `duration = last_seen − start_time = 8.0`; flow đóng bằng FIN hai chiều nên `CLOSED` / `tcp_closed`.