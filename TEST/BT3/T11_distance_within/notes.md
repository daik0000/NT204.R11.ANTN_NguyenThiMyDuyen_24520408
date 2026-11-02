# T11 – `distance`, `within` và quay lui

## Mục tiêu
Nhiều `content` có quan hệ tương đối: content sau được tìm trong cửa sổ tính từ **cuối** lần khớp của content trước (`prev_end + distance`, độ lớn `within`). Khi content sau không khớp, engine phải **quay lui**: thử lần xuất hiện kế tiếp của content trước, và rule chỉ trượt khi không còn cách nào cho cả chuỗi khớp. `matched` ghi vị trí của tổ hợp thành công.

## Input
- `rules.rules` (sid 11001–11004), 4 rule trên TCP, mỗi rule chỉ có `content` và các modifier tương đối. Rule 11001–11003 nhắm cổng đích 9001, rule 11004 nhắm cổng đích 9002; nhờ cổng đích mà mỗi rule chỉ áp dụng cho gói của nó.
- `input.pcap` (do `make_pcap.py` dựng, md5 cố định `0354dc9e8ebd18957ca81f3c1b0ab1c5`), 2 gói TCP (payload không phải HTTP, cổng 9001 và 9002 không có parser nên payload là byte thô):
  - gói 1: `10.0.0.1:40011 -> 10.0.0.2:9001`, payload `AAA-BBB-CCC-BBB` (15 byte)
  - gói 2: `10.0.0.1:40012 -> 10.0.0.2:9002`, payload `BBB----BBB-CCC` (14 byte)
- Biến thể (chạy riêng, thư mục `variant_more_windows/`): `variants.rules` (sid 11101–11110) chạy trên cùng `input.pcap`.
- Cách nạp: bài test chạy `main.py` với `--rules`; cấu hình tạm có `engine.rule_files: []` nên không có rule mẫu nào khác bị nạp.

## Kết quả mong đợi (tính tay trước khi chạy)
Vị trí: gói 1 là `AAA` 0..3, `-` ở 3, `BBB` 4..7, `-` ở 7, `CCC` 8..11, `-` ở 11, `BBB` 12..15. Gói 2 là `BBB` 0..3, `----` 3..7, `BBB` 7..10, `-` ở 10, `CCC` 11..14.

| sid | Rule | Tính | Kết quả |
|---|---|---|---|
| 11001 | `"AAA"; "BBB"; distance:1; within:3` | `AAA` kết thúc ở 3 ⇒ cửa sổ `[4, 7)`; `BBB` ở 4..7 nằm trọn | **MATCH**, `AAA` 0 và `BBB` 4 |
| 11002 | `"AAA"; "CCC"; distance:1; within:3` | cửa sổ `[4, 7)`; `CCC` ở 8..11, ngoài cửa sổ | NO MATCH |
| 11003 | `"BBB"; "BBB"; distance:1` | `BBB` đầu 4..7 ⇒ tìm từ 8 ⇒ `BBB` thứ hai ở 12 | **MATCH**, 4 và 12 |
| 11004 | `"BBB"; "CCC"; distance:1; within:3` (gói 2) | `BBB` ở 0 (kết thúc 3) ⇒ cửa sổ `[4, 7)` không có `CCC`; **quay lui**: `BBB` ở 7 (kết thúc 10) ⇒ cửa sổ `[11, 14)`, `CCC` ở 11..14 nằm trọn | **MATCH**, `BBB` 7 và `CCC` 11 |

- 3 Detection theo thứ tự: (gói 1, 11001), (gói 1, 11003), (gói 2, 11004). Gói 1 khớp rule 1 và 3, không khớp rule 2. Offset của `BBB` ở rule 11004 là **7**, không phải 0.
- Một bộ so khớp chỉ thử `BBB` đầu tiên sẽ trả NO MATCH sai cho 11004.
- Thống kê: rule 11001–11003 là ứng viên của gói 1, 11004 của gói 2 ⇒ `candidate_rules = 4`; cả 4 vào stage content: `content_evaluations = 4`, `rejected_content = 1` (11002), `matches = 3`. Tóm tắt cuối: `rules(loaded=4, invalid=0, unsupported=0), events_evaluated=2, candidates=4, detections=3`.

Biến thể (`variants.rules`; 11101–11107 cho gói 1, 11108–11110 cho gói 2):

| sid | Rule | Tính | Kết quả |
|---|---|---|---|
| 11101 | `"AAA"; "BBB"; within:4` (không `distance`) | cửa sổ bắt đầu ngay chỗ `AAA` kết thúc: `[3, 7)`; `BBB` 4..7 vừa | MATCH (0, 4) |
| 11102 | `"AAA"; "BBB"; within:3` | `[3, 6)`; `BBB` 4..7 vượt | NO |
| 11103 | `"BBB"; "BBB"; distance:0` | `BBB` 4..7, tìm từ 7: `BBB` ở 12 | MATCH (4, 12) |
| 11104 | `"BBB"; "BBB"; distance:-3` | `BBB` 4..7, bắt đầu 7 − 3 = 4: lại thấy `BBB` ở 4 (chồng lên lần khớp trước) | MATCH (4, 4) |
| 11105 | `"CCC"; "AAA"; distance:0` | `CCC` 8..11, sau đó không có `AAA` | NO |
| 11106 | `"AAA"; "CCC"; distance:4; within:3` | bắt đầu 3 + 4 = 7, cửa sổ `[7, 10)`; `CCC` 8..11 vượt 1 byte | NO |
| 11107 | `"AAA"; "CCC"; distance:4; within:4` | cửa sổ `[7, 11)`; `CCC` 8..11 vừa | MATCH (0, 8) |
| 11108 | `"BBB"; "CCC"; distance:1` | `BBB` ở 0 ⇒ `CCC` ở 11, không cần quay lui | MATCH (0, 11) |
| 11109 | `"BBB"; "CCC"; within:3` | `BBB` 0: `[3, 6)` không có; `BBB` 7: `[10, 13)`, `CCC` 11..14 vượt 1 byte | NO (quay lui cũng không đủ) |
| 11110 | `"BBB"; "BBB"; distance:1; "CCC"; distance:1; within:3` | `BBB` 0; `BBB` thứ hai từ 4 ⇒ 7; `CCC` trong `[11, 14)` ⇒ 11 | MATCH (0, 7, 11) |

⇒ 6 Detection: 11101, 11103, 11104, 11107 (gói 1) và 11108, 11110 (gói 2). `candidate_rules = 7 + 3 = 10`, `content_evaluations = 10`, `rejected_content = 4`, `matches = 6`. Tóm tắt: `events_evaluated=2, candidates=10, detections=6`.

## Kết quả thực tế
Chạy `pytest TEST/BT3/T11_distance_within`: **26 test pass**, mọi giá trị khớp bảng tính tay (không phải sửa kỳ vọng).

- `detections.jsonl`: 3 dòng — (gói 1, 11001) `AAA` 0, `BBB` 4; (gói 1, 11003) `BBB` 4, `BBB` 12; (gói 2, 11004) `BBB` 7, `CCC` 11. Không có 11002.
- Chứng minh quay lui: với 11004, `BBB` đầu tiên (offset 0) cho cửa sổ `[4, 7)` mà `find` không thấy `CCC`; bộ so khớp thật đi lại và trả `[(7, 3), (11, 3)]`. Với 11002, `AAA` kết thúc ở 3 cho cửa sổ `[4, 7)` còn `CCC` nằm ở 8.
- Thống kê: `candidate_rules=4, content_evaluations=4, rejected_content=1, matches=3, rule_errors=0`.
- Biến thể: `variant_more_windows/detections.jsonl` có 6 dòng đúng các sid và vị trí như bảng, kể cả (4, 4) của `distance:-3` và (0, 7, 11) của ba `content`; `candidates=10, rejected_content=4, matches=6`.
- `rules_report.jsonl`: 4 dòng `valid`; `main.py` exit 0; `input.pcap` dựng lại cho cùng md5; output hai lần chạy liên tiếp giống hệt từng byte.

## Bằng chứng trong thư mục
- Chạy chính, cạnh `input.pcap`: `rules_report.jsonl`, `events.jsonl`, `flows.jsonl`, `detections.jsonl`.
- Biến thể, trong `variant_more_windows/`: bốn file cùng tên.
- Do `main.py` ghi (qua `run_case_ids`), sinh lại mỗi lần chạy, không sửa tay; trường `file` là đường dẫn tương đối so với gốc repo.

## Kết luận
**PASS.**

Chạy: `pytest TEST/BT3/T11_distance_within`.
