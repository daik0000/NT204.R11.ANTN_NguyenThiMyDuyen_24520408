# T09 – TCP close

## Input
`input.pcap`, 17 gói TCP không payload (10.0.0.1 → 10.0.0.2:80), 3 kết nối, mỗi kết nối có handshake đầy đủ:
- Flow 1 (port 40301): đóng bình thường – FIN/ACK client, ACK server, FIN/ACK server, ACK cuối của client.
- Flow 2 (port 40302): RST từ client, sau đó thêm 1 ACK muộn từ server (biến thể phụ).
- Flow 3 (port 40303): half-close – chỉ client gửi FIN/ACK, server chỉ ACK rồi im.

## Kết quả mong đợi (tính tay)
Mặc định `tcp_close_requires_final_ack: false`: thấy đủ FIN hai chiều là `CLOSED`.
Gói muộn sau trạng thái kết thúc (`CLOSED`/`RESET`) không đổi state nhưng vẫn được tính vào flow.

| Gói | Flow | Flags | Hướng | flow_state |
|---|---|---|---|---|
| 1,2,3 | 1 | SYN, SYN/ACK, ACK | F,B,F | HANDSHAKE, HANDSHAKE, ESTABLISHED |
| 4 | 1 | FIN/ACK | F | CLOSING |
| 5 | 1 | ACK | B | CLOSING (chưa đủ 2 FIN) |
| 6 | 1 | FIN/ACK | B | **CLOSED** |
| 7 | 1 | ACK cuối | F | CLOSED (không đổi) |
| 8,9,10 | 2 | SYN, SYN/ACK, ACK | F,B,F | HANDSHAKE, HANDSHAKE, ESTABLISHED |
| 11 | 2 | RST | F | **RESET** |
| 12 | 2 | ACK muộn | B | RESET (không đổi) |
| 13,14,15 | 3 | SYN, SYN/ACK, ACK | F,B,F | HANDSHAKE, HANDSHAKE, ESTABLISHED |
| 16 | 3 | FIN/ACK | F | CLOSING |
| 17 | 3 | ACK | B | CLOSING |

Mọi gói `raw_length = 54`.

| Flow | packets (fwd/bwd) | byte | syn / ack / fin / rst | state | close_reason | duration |
|---|---|---|---|---|---|---|
| 1 (40301) | 7 (4/3) | 378 | 2 / 6 / 2 / 0 | CLOSED | tcp_closed | 6.0 |
| 2 (40302) | 5 (3/2) | 270 | 2 / 3 / 0 / 1 | RESET | tcp_reset | 4.0 |
| 3 (40303) | 5 (3/2) | 270 | 2 / 4 / 1 / 0 | CLOSING | flush | 2.0 |

Lưu ý: toàn bộ pcap dài 14 giây nên flow 1 (CLOSED lúc T+5, linger 10 giây) chưa hết hạn trước khi kết thúc;
flush giữ nguyên `tcp_closed`/`tcp_reset`, flow 3 không hoàn tất đóng nên nhận `flush`.

## Kết quả thực tế
- `events.jsonl`: 17 event, tất cả `status=OK`, `raw_length=54`, `processing_action=defaults_filled`
  (không payload). `direction`/`flow_state` từng gói trùng bảng mong đợi:
  - Flow 1: HANDSHAKE, HANDSHAKE, ESTABLISHED, CLOSING (FIN đầu), CLOSING (ACK), CLOSED (FIN thứ hai), CLOSED (ACK cuối).
  - Flow 2: HANDSHAKE, HANDSHAKE, ESTABLISHED, RESET (RST), RESET (ACK muộn).
  - Flow 3: HANDSHAKE, HANDSHAKE, ESTABLISHED, CLOSING (FIN), CLOSING (ACK).
- `flows.jsonl`: 3 flow.
  - 1 (f320a8cedb1e6a67): packet 7 (4/3), byte 378 (216/162), syn 2, ack 6, fin 2, rst 0,
    CLOSED, close_reason=tcp_closed, duration 6.0.
  - 2 (9cc6052e05e04e93): packet 5 (3/2), byte 270 (162/108), syn 2, ack 3, fin 0, rst 1,
    RESET, close_reason=tcp_reset, duration 4.0.
  - 3 (22baf516ad44ee1b): packet 5 (3/2), byte 270 (162/108), syn 2, ack 4, fin 1, rst 0,
    CLOSING, close_reason=flush, duration 2.0.
  - Cả ba: midstream=false, payload_byte_count=0.

## Kết luận
**PASS** – khớp 100% giá trị tính tay.
- Đóng bình thường: `CLOSED` đúng lúc thấy FIN thứ hai (gói 6), không đợi ACK cuối; ACK cuối (gói 7)
  vẫn được tính vào cùng flow (packet_count=7, ack_count=6) mà state giữ `CLOSED`.
- RST đưa flow sang `RESET` ngay, và ACK muộn (gói 12) không đổi state nhưng vẫn được tính (packet_count=5).
- Half-close chỉ có một FIN nên dừng ở `CLOSING` và nhận `close_reason=flush` khi pcap kết thúc,
  còn `CLOSED`/`RESET` giữ `tcp_closed`/`tcp_reset` khi flush.
- Cấu hình mặc định `tcp_close_requires_final_ack=false` và linger 10 giây phù hợp với kịch bản này.