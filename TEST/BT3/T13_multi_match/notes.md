# T13 – Nhiều rule cùng khớp một gói

## Mục tiêu
Một gói có thể khớp nhiều rule cùng lúc; engine phải báo **tất cả**, theo thứ tự rule trong file, và **không dừng ở rule khớp đầu tiên**. Mỗi Detection có `packet_id` của gói đó, và `matched` của từng rule ghi đúng phần đã khớp (rule chỉ có header và flow thì ghi `[{"keyword": "header"}]`).

## Input
- `rules.rules` (sid 100001–100004), tất cả có header `alert tcp any any -> any 80`:

| sid | Option |
|---|---|
| 100001 | `content:"../"` |
| 100002 | `content:"/etc/passwd"` |
| 100003 | `flow:to_server,established; dsize:>0` (chỉ header + flow, không có `content`) |
| 100004 | `content:"/etc/shadow"` (không có trong gói) |

  Rule 100003 có thêm `dsize:>0` để không bắn luôn cả gói ACK thuần (gói đó cũng `established` và gửi tới server); nhờ vậy 100003 chỉ khớp gói yêu cầu.
- `input.pcap` (do `make_pcap.py` dựng, md5 cố định `e079e413284a5347594a6c76277679a8`), bắt tay đủ rồi một yêu cầu, từ `10.0.0.5:52133` tới `192.168.1.20:80`: p1 SYN, p2 SYN/ACK, p3 ACK (flow thành `ESTABLISHED`), p4 `GET /../../etc/passwd HTTP/1.1` (payload 53 byte, kèm `Host`).
- Biến thể (chạy riêng, thư mục `variant_other_rules/`): `variants.rules` (sid 13101–13106) chạy trên cùng `input.pcap`.
- Cách nạp: bài test chạy `main.py` với `--rules`; cấu hình tạm có `engine.rule_files: []` nên không có rule mẫu nào khác bị nạp.

## Kết quả mong đợi (tính tay trước khi chạy)
Vị trí trong payload `GET /../../etc/passwd HTTP/1.1`: `GET ` chiếm 0..3, `/` ở 4, `../` ở 5..8 và lần nữa ở 8..11, `/etc/passwd` bắt đầu ở 10 (dấu `/` cuối của `../` thứ hai) dài 11 byte, `HTTP/1.1` ở 22.

| sid | Gói 4 | `matched` |
|---|---|---|
| 100001 | **MATCH** | `../`, offset 5, length 3 |
| 100002 | **MATCH** | `/etc/passwd`, offset 10, length 11 |
| 100003 | **MATCH** (to_server, established, payload > 0) | `[{"keyword": "header"}]` |
| 100004 | không | – |

- **3 Detection cho cùng `packet_id = 4`**, theo thứ tự `100001, 100002, 100003`; không có 100004. Cả ba cùng `timestamp`, 5-tuple, `flow_id` và `flow_direction = to_server`; chỉ `sid`, `msg` và `matched` khác nhau.
- p1 (SYN), p2 (SYN/ACK) và p3 (ACK, payload rỗng) không có Detection nào.
- Trạng thái flow sau từng gói: `HANDSHAKE, HANDSHAKE, ESTABLISHED, ESTABLISHED`.
- Thống kê: cả 4 rule là ứng viên của 3 gói gửi tới cổng 80 (p1, p3, p4; p2 gửi tới cổng 52133) ⇒ `candidate_rules = 12`:
  - p1 (SYN, chưa established, rỗng): 100001, 100002, 100004 vào stage content và trượt (3); 100003 trượt ở flow (1).
  - p3 (ACK, established, rỗng): 100001, 100002, 100004 trượt ở content (3); 100003 qua flow nhưng trượt `dsize` (1, stage packet).
  - p4: 100001, 100002, 100004 vào content (100004 trượt); 100003 khớp.
  - ⇒ `rejected_flow = 1`, `rejected_packet = 1`, `content_evaluations = 9`, `rejected_content = 3 + 3 + 1 = 7`, `matches = 3`; kiểm tra: 12 = 1 + 1 + 7 + 3.
- `stats.matches = 3` và `candidate_rules ≥ 4` (thực tế 12).
- Tóm tắt cuối: `rules(loaded=4, invalid=0, unsupported=0), events_evaluated=4, candidates=12, detections=3`.

Biến thể (`variants.rules`, cùng phiên; flow `ESTABLISHED` ở p3 và p4):

| sid | Rule | Gói 4 | `matched` |
|---|---|---|---|
| 13101 | `content:"passwd"` | MATCH | `passwd` 15 |
| 13102 | `content:"etc"; content:"passwd"; distance:1` | MATCH | `etc` 11, `passwd` 15 (`etc` kết thúc ở 14, tìm từ 15) |
| 13103 | `flow:to_client,established; content:"../"` | không | yêu cầu gửi tới server, sai vai trò |
| 13104 | `content:"../"; content:"../"; distance:0` | MATCH | `../` 5, `../` 8 |
| 13105 | `content:"http/1.1"; nocase` | MATCH | `http/1.1` 22 |
| 13106 | `dsize:>1000; content:"../"` | không | payload chỉ 53 byte |

⇒ 4 Detection (13101, 13102, 13104, 13105), cùng `packet_id = 4`. Thống kê: `candidate_rules = 6 × 3 = 18`, `rejected_flow = 3` (13103 ở p1, p3, p4), `rejected_packet = 3` (13106), `content_evaluations = 12` (4 ở mỗi gói p1, p3, p4), `rejected_content = 8` (4 ở p1 và 4 ở p3), `matches = 4`. Tóm tắt: `events_evaluated=4, candidates=18, detections=4`.

## Kết quả thực tế
Chạy `pytest TEST/BT3/T13_multi_match`: **19 test pass**, mọi giá trị khớp bảng tính tay (không phải sửa kỳ vọng).

- `detections.jsonl`: 3 dòng, đều `packet_id = 4`, `flow_direction = to_server`, theo thứ tự 100001 (`../` 5), 100002 (`/etc/passwd` 10), 100003 (`header`). Không có 100004. Trạng thái flow của bốn event: `HANDSHAKE, HANDSHAKE, ESTABLISHED, ESTABLISHED`.
- Thống kê: `candidate_rules=12, rejected_flow=1, rejected_packet=1, content_evaluations=9, rejected_content=7, matches=3, rule_errors=0`.
- Đối tượng `Engine` chạy trực tiếp trên pcap (không qua `main.py`): lần gọi `process` cuối trả về cả ba Detection `[100001, 100002, 100003]`, `stats.matches = 3`, `candidate_rules ≥ 4`, `is_consistent()` đúng.
- Biến thể: `variant_other_rules/detections.jsonl` có 4 dòng như bảng; `candidates=18, rejected_flow=3, rejected_packet=3, content_evaluations=12, rejected_content=8, matches=4`.
- `rules_report.jsonl`: 4 dòng `valid`; `main.py` exit 0; `input.pcap` dựng lại cho cùng md5; output hai lần chạy liên tiếp giống hệt từng byte.

## Bằng chứng trong thư mục
- Chạy chính, cạnh `input.pcap`: `rules_report.jsonl`, `events.jsonl`, `flows.jsonl`, `detections.jsonl`.
- Biến thể, trong `variant_other_rules/`: bốn file cùng tên.
- Do `main.py` ghi (qua `run_case_ids`), sinh lại mỗi lần chạy, không sửa tay; trường `file` là đường dẫn tương đối so với gốc repo.

## Kết luận
**PASS.**

Chạy: `pytest TEST/BT3/T13_multi_match`.
