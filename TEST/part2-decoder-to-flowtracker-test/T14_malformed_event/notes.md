# T14 – Malformed event

## Input
**Nửa A – `input.pcap`, 5 gói (T = 1700000000), chạy 3 lần:**
| Gói | t | Nội dung |
|---|---|---|
| 1 | 0 | Cắt trong header IPv4: Ethernet 14 byte + 6 byte IP (frame 20 byte) |
| 2 | 1 | ICMP echo request (IPv4 nhưng transport không hỗ trợ) |
| 3 | 2 | ARP request (không phải IPv4) |
| 4 | 3 | Cắt trong header TCP: Ethernet + IPv4 đủ + 10 byte TCP (frame 44 byte) |
| 5 | 4 | SYN hợp lệ 10.0.0.1:40701 → 10.0.0.2:80 (cuối pcap) |

Ba lần chạy: mặc định (`invalid_policy: flag`, `unsupported_policy: mark`), `settings_drop.yaml` (`invalid_policy: drop`),
`settings_skip.yaml` (`unsupported_policy: skip`). Output được lưu thành `events_<flag|drop|skip>.jsonl` và `flows_<...>.jsonl`.

**Nửa B – event tổng hợp (`IDSEvent`):** `src_port=70000`; `timestamp=NaN`; thiếu `src_ip`; một event hợp lệ ở cuối;
chạy với `invalid_policy` = `flag` rồi `drop`; thêm một lần gọi `preprocess_event` với cấu hình thiếu mục `preprocessor`.

## Kết quả mong đợi (tính tay)
| Gói / event | preprocess_status | processing_action (flag) | reason |
|---|---|---|---|
| 1 (cắt IPv4) | invalid | flagged | `malformed_<layer>` (layer lấy từ `error_info.layer`) |
| 2 ICMP | partial | flagged | `unsupported_transport:ICMP` |
| 3 ARP | partial | flagged | `unsupported_network` |
| 4 (cắt TCP) | invalid | flagged | `malformed_<layer>` |
| 5 SYN hợp lệ | valid | defaults_filled | (rỗng) |
| port 70000 | invalid | flagged | `invalid_src_port` |
| timestamp NaN | invalid | flagged | `invalid_timestamp` |
| thiếu src_ip | invalid | flagged | `missing_src_ip` |

- Mọi event invalid/unsupported có `flow_id = null`, `direction = null`, `flow_state = null`: không tạo flow rác.
  `flows.jsonl` chỉ có đúng 1 flow (gói 5: packet 1, byte 54).
- Số dòng trong `events.jsonl`:
  - `flag/mark`: 5 dòng (gói 1–5).
  - `drop`: 3 dòng (gói 2, 3, 5; gói 1 và 4 bị `dropped` nên không có dòng log; event tổng hợp ra `processing_action=dropped`).
  - `skip`: 3 dòng (gói 1, 4, 5; gói 2 và 3 bị `skipped`).
- Cấu hình hỏng (thiếu `preprocessor`): không crash, verdict fail-safe `invalid` / `flagged`, `error_info.layer = "preprocessor"`.
- Chương trình không crash ở bất kỳ lần chạy nào (`main.py` thoát với mã 0).

## Kết quả thực tế
Mặc định (`invalid_policy: flag`, `unsupported_policy: mark`) – `events_flag.jsonl`, 5 dòng:
| Gói | status | preprocess_status | processing_action | reason | flow_id |
|---|---|---|---|---|---|
| 1 (cắt IPv4, 20 byte) | MALFORMED, `error_info.layer=parse_ipv4` | invalid | flagged | `malformed_parse_ipv4` | null |
| 2 ICMP | OK, `ip_proto_number=1` | partial | flagged | `unsupported_transport:ICMP` | null |
| 3 ARP | UNKNOWN | partial | flagged | `unsupported_network` | null |
| 4 (cắt TCP, 44 byte) | MALFORMED, `error_info.layer=parse_tcp` | invalid | flagged | `malformed_parse_tcp` | null |
| 5 SYN hợp lệ | OK | valid | defaults_filled | (rỗng) | 7b94a8e1b8293173 |

- `flows_flag.jsonl`: đúng 1 flow (7b94a8e1b8293173): TCP 10.0.0.1:40701 → 10.0.0.2:80, packet 1, byte 54,
  syn 1, HANDSHAKE, `close_reason=flush`. Không có flow nào cho gói 1–4.
- `events_drop.jsonl` (`invalid_policy: drop`): packet_id = [2, 3, 5] – gói 1 và 4 không có dòng log.
- `events_skip.jsonl` (`unsupported_policy: skip`): packet_id = [1, 4, 5] – gói 2 và 3 không có dòng log.
- Nửa B (event tổng hợp, 18 test pytest pass): port 70000 → `invalid_src_port`, timestamp NaN → `invalid_timestamp`,
  thiếu `src_ip` → `missing_src_ip`; `flag` cho `flagged`, `drop` cho `dropped`, `flow_id=null`; event hợp lệ ở cuối vẫn tạo flow;
  cấu hình thiếu mục `preprocessor` cho `invalid`/`flagged` với `error_info.layer="preprocessor"`.

## Kết luận
**PASS**
- Gói hỏng không tạo flow rác: gói 4 vẫn giữ `src_ip`/`dst_ip` của tầng Network nhưng thiếu cổng nên `flow_id=null`.
- `invalid_policy` chỉ quyết định việc ghi log của event invalid (`drop` bỏ gói 1, 4); `unsupported_policy` chỉ quyết định
  việc ghi log của ICMP/ARP (`skip` bỏ gói 2, 3). Hai policy độc lập với nhau.
- Gói hợp lệ ở cuối pcap vẫn tạo flow bình thường sau bốn gói hỏng liên tiếp.
- Ghi chú: `error_info.layer` là tên hàm parser (`parse_ipv4`, `parse_tcp`), nên reason có dạng `malformed_parse_ipv4`
  chứ không phải `malformed_network`. Event MALFORMED có `timestamp_iso=null` và `decode_status=null`
  (Decoder bị bỏ qua), còn ICMP/ARP có `decode_status=SKIPPED` và `timestamp_iso` bình thường.