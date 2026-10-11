# T12 – Idle timeout

## Input
`settings.yaml` riêng: `udp_idle_timeout_sec=5`, `tcp_idle_timeout_sec=5`, `tcp_handshake_timeout_sec=3`, `sweep_interval_sec=1`
(truyền qua `--config`). Timeout tính theo thời gian của gói, nên không cần `sleep`.

`input.pcap`, 8 gói (T = 1700000000):
| Gói | t | Flow | Nội dung |
|---|---|---|---|
| 1 | 0.0 | U | UDP 10.0.0.1:50001 → 10.0.0.2:9000 "hi" |
| 2 | 0.5 | E | TCP :40501 → :9100 SYN |
| 3 | 0.75 | H | TCP :40502 → :9200 SYN, không ai trả lời |
| 4 | 1.0 | U | UDP trả lời (last_seen của U = 1.0) |
| 5 | 1.5 | E | SYN/ACK |
| 6 | 2.0 | E | ACK → ESTABLISHED (last_seen của E = 2.0) |
| 7 | 8.0 | U' | **biến thể phụ:** cùng 5-tuple với U, sau timeout |
| 8 | 20.0 | X | 10.0.0.9:50009 → :9300 SYN, gói không liên quan |

## Kết quả mong đợi (tính tay)
Hết hạn khi `now − last_seen > timeout` (bằng nhau thì chưa hết hạn).
- Gói 7 (t=8): U có 8 − 1 = 7 > 5 → hết hạn **ngay lúc gói đến** (lazy), xuất `idle_timeout`; gói 7 mở **flow mới** U2 với `flow_id` khác.
  Sweep sau gói 7: E có 8 − 2 = 6 > 5 → `idle_timeout`; H (HANDSHAKE) có 8 − 0.75 = 7.25 > 3 → `handshake_timeout`.
- Gói 8 (t=20): sweep thấy U2 có 20 − 8 = 12 > 5 → `idle_timeout`. X còn mở đến cuối pcap → `flush`.

| Flow | packets (fwd/bwd) | byte | state | duration | close_reason |
|---|---|---|---|---|---|
| U (50001) | 2 (1/1) | 88 | ACTIVE | 1.0 | idle_timeout |
| E (40501) | 3 (2/1) | 162 | ESTABLISHED | 1.5 | idle_timeout |
| H (40502) | 1 (1/0) | 54 | HANDSHAKE | 0.0 | handshake_timeout |
| U2 (50001) | 1 (1/0) | 44 | ACTIVE | 0.0 | idle_timeout |
| X (50009) | 1 (1/0) | 54 | HANDSHAKE | 0.0 | flush |

Gói UDP `"hi"` = 14 + 20 + 8 + 2 = 44. Có 5 flow; 4 flow đầu nằm trong `flows.jsonl` **trước** dòng flush của X.
Qua API: `active_flow_count()` = 3 sau 3 gói đầu, rồi còn 1 sau gói t=8 (đã loại U, E, H khỏi active table).

## Kết quả thực tế
- `events.jsonl`: 8 event, tất cả `status=OK`, `preprocess_status=valid`.
  `flow_state`: gói 1/4/7 (UDP) = ACTIVE; gói 2, 3, 5 = HANDSHAKE; gói 6 = ESTABLISHED; gói 8 = HANDSHAKE.
  **Gói 7 (t=8) cùng 5-tuple với gói 1 nhưng `flow_id` khác** (200a3723… so với 3fd08987…), direction forward.
- `flows.jsonl`: 5 dòng, theo đúng thứ tự xuất flow: U, H, E, U2, X (4 flow hết hạn trước, dòng `flush` cuối cùng).
  - U (3fd089876ab72d5e): UDP, packet 2 (1/1), byte 88, payload 4, duration 1.0, `idle_timeout`.
  - H (cc58046b2ecbe58b): TCP :40502, packet 1, byte 54, syn 1, HANDSHAKE, duration 0.0, `handshake_timeout`.
  - E (5e4527bc22431af5): TCP :40501, packet 3 (2/1), byte 162, ESTABLISHED, duration 1.5, `idle_timeout`.
  - U2 (200a37236051aaf7): UDP, packet 1, byte 44, payload 2, start 1700000008.0, `idle_timeout`.
  - X (b0c4bd95f737927a): TCP 10.0.0.9:50009, packet 1, byte 54, HANDSHAKE, `flush`.

## Kết luận
**PASS** 
- Gói UDP đến sau timeout (8 − 1 = 7 > 5) làm flow cũ hết hạn ngay (`idle_timeout`) và mở flow mới
  (khác `flow_id`, `start_time=…008.0`), không bị nuốt vào flow cũ.
- Sau gói t=8, sweep đưa E ra bằng `idle_timeout` (8 − 2 = 6 > 5) và H bằng `handshake_timeout`
  (8 − 0.75 > 3); SYN không hồi đáp kết thúc ở HANDSHAKE rồi mới hết hạn, đúng thiết kế dữ liệu nền cho phát hiện port scan.
- Gói t=20 đưa U2 ra (`idle_timeout`); chỉ X còn mở đến cuối pcap nên nhận `flush`.
- `active_flow_count()` giảm 3 → 1 sau gói t=8 (test in-process).
- Ghi chú: UDP port 9000 có `app_protocol=UNKNOWN` (`detection_method=null`), `payload_length=10` (8 UDP header + 2).