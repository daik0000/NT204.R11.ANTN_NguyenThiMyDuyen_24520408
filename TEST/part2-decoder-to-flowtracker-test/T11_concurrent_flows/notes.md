# T11 – Concurrent flows

## Input
`input.pcap`, 13 gói xen kẽ của 5 kết nối (packet i gửi lúc T + 0.25·(i−1)):
- F1 TCP 10.0.0.1:40401 → 10.0.0.2:9000 (gói 1, 5, 11): handshake đầy đủ.
- F2 TCP 10.0.0.1:40402 → 10.0.0.2:9000 (gói 2, 7, 12): cùng IP, khác source port.
- F3 TCP 10.0.0.1:40401 → 10.0.0.2:9001 (gói 3, 8, 13): cùng IP và source port, khác destination port.
- F4 TCP 10.0.0.3:40401 → 10.0.0.4:9000 (gói 4, 9): khác hẳn IP, chỉ SYN và SYN/ACK.
- F5 UDP 10.0.0.1:40401 → 10.0.0.2:9000 (gói 6, 10): `ping`/`pong`, cùng IP/port với F1 nhưng khác protocol.

## Kết quả mong đợi (tính tay)
Gói TCP không payload: 14 + 20 + 20 = 54. Gói UDP: 14 + 20 + 8 + 4 = 46. Có đúng **5 flow**, không flow nào bị tách hoặc gộp.

| Flow | endpoint_a → endpoint_b | packets (fwd/bwd) | byte (fwd/bwd) | syn / ack | state | duration |
|---|---|---|---|---|---|---|
| F1 | 10.0.0.1:40401 → 10.0.0.2:9000 | 3 (2/1) | 162 (108/54) | 2 / 2 | ESTABLISHED | 2.5 |
| F2 | 10.0.0.1:40402 → 10.0.0.2:9000 | 3 (2/1) | 162 (108/54) | 2 / 2 | ESTABLISHED | 2.5 |
| F3 | 10.0.0.1:40401 → 10.0.0.2:9001 | 3 (2/1) | 162 (108/54) | 2 / 2 | ESTABLISHED | 2.5 |
| F4 | 10.0.0.3:40401 → 10.0.0.4:9000 | 2 (1/1) | 108 (54/54) | 2 / 1 | HANDSHAKE | 1.25 |
| F5 (UDP) | 10.0.0.1:40401 → 10.0.0.2:9000 | 2 (1/1) | 92 (46/46) | 0 / 0 | ACTIVE | 1.0 |

Tổng packet = 3+3+3+2+2 = 13 (bằng số gói trong pcap). Tất cả: `close_reason=flush`, `midstream=false`, fin=rst=0.
`direction` tính theo người gửi đầu tiên của *từng* flow (gói 8 và 9 là backward; gói 10 là backward).

## Kết quả thực tế
- `events.jsonl`: 13 event, tất cả `status=OK`, `raw_length` = 54 (TCP) / 46 (hai gói UDP: gói 6, 10).
  `direction`/`flow_state` từng gói trùng bảng mong đợi (gói 8, 9, 10 = backward; F4 dừng ở HANDSHAKE).
- `flows.jsonl`: 5 flow (flush theo thứ tự last_seen tăng dần).
  - F4 (572887c7efb71722): packet 2 (1/1), byte 108, syn 2, ack 1, HANDSHAKE, duration 1.25.
  - F5 UDP (6dad08c72a21dda4): packet 2 (1/1), byte 92 (46/46), payload 8, ACTIVE, duration 1.0.
  - F1 (ddebdafd0f4dc301), F2 (a61c13d8276df06d), F3 (15972b84acb36674): mỗi flow packet 3 (2/1),
    byte 162 (108/54), syn 2, ack 2, ESTABLISHED, duration 2.5.
  - Cả năm: close_reason=flush, midstream=false, fin=rst=0.

## Kết luận
**PASS** 
- Năm 5-tuple khác nhau đúng một yếu tố (source port, destination port, cặp IP, protocol) cho ra
  đúng 5 flow riêng với 5 `flow_id` khác nhau, dù các gói xen kẽ nhau trên dây.
- TCP và UDP cùng 10.0.0.1:40401 → 10.0.0.2:9000 là hai flow khác nhau, nên `protocol` nằm trong key.
- `direction` tính theo người gửi đầu tiên của từng flow (F4: gói 9 từ 10.0.0.4 là backward).
- Ghi chú: gói UDP port 9000 không có parser riêng nên `app_protocol=UNKNOWN`, `detection_method=null`,
  và `application_protocol` của F5 là `UNKNOWN`; `payload_length` = 12 (8 UDP header + 4 byte dữ liệu).