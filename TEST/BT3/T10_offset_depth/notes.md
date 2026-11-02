# T10 – `offset` và `depth`

## Mục tiêu
`offset:N` và `depth:N` giới hạn vùng tìm của `content` thành cửa sổ `[offset, offset + depth)`. **`depth` là kích thước cửa sổ tính từ `offset`, không phải vị trí tuyệt đối.** Pattern phải nằm trọn trong cửa sổ; không có `depth` thì cửa sổ chạy đến hết payload; không có `offset` thì bắt đầu từ 0. `offset` lớn hơn độ dài payload cho cửa sổ rỗng, tức là không khớp, không phải lỗi.

## Input
- `rules.rules` (sid 10001–10006), tất cả có header `alert udp any any -> any 9999` và chỉ có `content` với `offset`/`depth`.
- `input.pcap` (do `make_pcap.py` dựng, md5 cố định `31775757da6ad04da9ddfb8e8ddc2793`): một datagram UDP `10.0.0.1:40010 -> 10.0.0.2:9999` có payload 10 byte `ABCDEFGHIJ` (cổng 9999 không có parser nên payload là byte thô).
- Biến thể (chạy riêng, thư mục `variant_edges/`): `variants.rules` (sid 10101–10108) chạy trên **cùng** `input.pcap`.
- Cách nạp: bài test chạy `main.py` với `--rules`; cấu hình tạm có `engine.rule_files: []` nên không có rule mẫu nào khác bị nạp.

## Kết quả mong đợi (tính tay trước khi chạy)
Payload: `A`=0 `B`=1 `C`=2 `D`=3 `E`=4 `F`=5 `G`=6 `H`=7 `I`=8 `J`=9. `CD` nằm ở byte 2..4; `J` ở byte 9..10.

| sid | Rule | Cửa sổ | Pattern có nằm trọn trong cửa sổ? | Kết quả |
|---|---|---|---|---|
| 10001 | `"CD"; offset:2; depth:2` | `[2, 4)` | `CD` = 2..4: có | **MATCH**, offset 2 |
| 10002 | `"CD"; offset:3` | `[3, 10)` | `CD` bắt đầu ở 2, trước cửa sổ | NO MATCH |
| 10003 | `"CD"; depth:3` | `[0, 3)` | `CD` kết thúc ở 4, vượt cửa sổ | NO MATCH |
| 10004 | `"CD"; depth:4` | `[0, 4)` | `CD` = 2..4: có | **MATCH**, offset 2 |
| 10005 | `"J"; offset:9` | `[9, 10)` | `J` = 9..10: có | **MATCH**, offset 9 |
| 10006 | `"J"; offset:10` | `[10, 10)` | cửa sổ rỗng | NO MATCH |

- 3 Detection (10001, 10004, 10005), theo thứ tự rule, với `matched[0].offset` = **2, 2, 9** (length 2, 2, 1; `value` là `CD`, `CD`, `J`).
- Nếu `depth` bị hiểu là vị trí tuyệt đối thì rule 10001 sẽ có cửa sổ rỗng `[2, 2)` và không khớp; vì vậy rule 10001 là phép thử cho điều này.
- Thống kê: cả 6 rule đều là ứng viên và đều vào stage content: `candidate_rules = 6`, `content_evaluations = 6`, `rejected_content = 3` (10002, 10003, 10006), `matches = 3`, các `rejected_header/flow/packet = 0`. Tóm tắt cuối: `rules(loaded=6, invalid=0, unsupported=0), events_evaluated=1, candidates=6, detections=3`.

Biến thể (`variants.rules`, cùng payload):

| sid | Rule | Cửa sổ | Kết quả |
|---|---|---|---|
| 10101 | `"A"; depth:1` | `[0, 1)` | **MATCH**, offset 0 |
| 10102 | `"IJ"; offset:8; depth:2` | `[8, 10)` | **MATCH**, offset 8 |
| 10103 | `"IJ"; offset:7; depth:2` | `[7, 9)` | NO MATCH (`IJ` kết thúc ở 10, vượt cửa sổ) |
| 10104 | `"CD"; offset:0; depth:4` | `[0, 4)` | **MATCH**, offset 2 |
| 10105 | `"EF"; offset:4; depth:2` | `[4, 6)` | **MATCH**, offset 4 |
| 10106 | `"EF"; offset:5` | `[5, 10)` | NO MATCH (`EF` bắt đầu ở 4) |
| 10107 | `"J"; offset:20` | offset vượt payload ⇒ rỗng | NO MATCH, không lỗi |
| 10108 | `"A"; offset:0` | `[0, 10)` | **MATCH**, offset 0 (`offset:0` tường minh giống như không có `offset`) |

⇒ 5 Detection: 10101, 10102, 10104, 10105, 10108 với offset 0, 8, 2, 4, 0; `candidate_rules = 8`, `content_evaluations = 8`, `rejected_content = 3`, `matches = 5`. Tóm tắt: `events_evaluated=1, candidates=8, detections=5`.

## Kết quả thực tế
Chạy `pytest TEST/BT3/T10_offset_depth`: **32 test pass**, mọi giá trị khớp bảng tính tay (không phải sửa kỳ vọng).

- Cửa sổ tính ra từ rule đã biên dịch đúng như bảng (ví dụ 10001 ra `(2, 4)`, 10003 ra `(0, 3)`, 10006 ra `(10, None)`); tìm trực tiếp trên payload cho đúng offset hoặc không thấy.
- Chạy chính: `detections.jsonl` có 3 dòng (10001, 10004, 10005) với `matched` = `CD`/2/2, `CD`/2/2, `J`/9/1; không có 10002, 10003, 10006. Thống kê: `candidate_rules=6, content_evaluations=6, rejected_content=3, matches=3, rule_errors=0`. Gói là UDP tới cổng 9999, `application_protocol = UNKNOWN`.
- Biến thể: `variant_edges/detections.jsonl` có 5 dòng (10101, 10102, 10104, 10105, 10108) với offset 0, 8, 2, 4, 0; `rule_errors=0` (kể cả rule `offset:20`); `candidates=8, rejected_content=3, matches=5`.
- `rules_report.jsonl`: 6 dòng `valid`; `main.py` exit 0; `input.pcap` dựng lại cho cùng md5; output hai lần chạy liên tiếp giống hệt từng byte.

## Bằng chứng trong thư mục
- Chạy chính, cạnh `input.pcap`: `rules_report.jsonl`, `events.jsonl`, `flows.jsonl`, `detections.jsonl`.
- Biến thể, trong `variant_edges/`: bốn file cùng tên.
- Do `main.py` ghi (qua `run_case_ids`), sinh lại mỗi lần chạy, không sửa tay; trường `file` là đường dẫn tương đối so với gốc repo.

## Kết luận
**PASS.**

Chạy: `pytest TEST/BT3/T10_offset_depth`.
