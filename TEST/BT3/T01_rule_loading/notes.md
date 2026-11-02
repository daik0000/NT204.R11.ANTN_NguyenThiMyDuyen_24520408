# T01 – Nạp rule từ file

## Mục tiêu
Chứng minh Loader đọc file rule đúng: bỏ comment và dòng trống, nối rule viết trên nhiều dòng bằng `\`, chỉ đưa các dòng rule thật sang Parser, bỏ qua file có `enabled: false`, và ghi nhận rule bị tắt bằng `disabled_sids` mà không đưa vào Repository.

## Input
`rules.rules` (11 dòng vật lý):

| Dòng | Nội dung | Loại |
|---|---|---|
| 1 | `# T01 - rule loading: ...` | comment |
| 2 | `# the second real rule (sid 1002) ...` | comment |
| 3 | (trống) | blank |
| 4 | `alert tcp any any -> any 80 (msg:"T01 rule 1001"; content:"GET"; sid:1001;)` | **rule** |
| 5 | `   # an indented comment` | comment (thụt lề) |
| 6 | (trống) | blank |
| 7 | (chỉ có 4 dấu cách) | blank |
| 8 | `# alert tcp any any -> any 80 (... sid:1999;)` | comment (rule bị comment) |
| 9–10 | `alert tcp ... (msg:"T01 rule 1002"; \` + `    content:"POST"; sid:1002;)` | **rule** (nối hai dòng) |
| 11 | `alert udp any any -> any 53 (msg:"T01 rule 1003"; sid:1003;)` | **rule** |

`disabled.rules`: một rule (sid 2001), được khai báo trong `engine.rule_files` với `enabled: false`.
`input.pcap` (do `make_pcap.py` dựng, md5 cố định): một gói SYN, chỉ để `main.py` chạy được.

Hai lần chạy (cùng `rules.rules`):
- **Chạy 1:** cả hai file nằm trong `engine.rule_files`, `disabled.rules` có `enabled: false`.
- **Chạy 2:** như chạy 1, thêm `disabled_sids: [1002]` (`config_disabled_sids.yaml`).

## Kết quả mong đợi (tính tay từ file, trước khi chạy)
Đếm theo **dòng logic** (dòng 9–10 là một):

| Bộ đếm | Chạy 1 | Chạy 2 (`disabled_sids: [1002]`) | Cách tính |
|---|---|---|---|
| `comment` | 4 | 4 | dòng 1, 2, 5, 8 |
| `blank` | 3 | 3 | dòng 3, 6, 7 |
| `rule_lines` | 3 | 3 | dòng 4, 9–10, 11 |
| `total_lines` | 10 | 10 | 4 + 3 + 3 |
| `valid` | 3 | **2** | rule tắt không tính vào `valid` |
| `invalid`, `unsupported` | 0, 0 | 0, 0 | cả 3 rule hợp lệ |
| `disabled` | 0 | **1** | sid 1002 |
| `disabled_files` | 1 | 1 | `disabled.rules` |
| `files_failed` | 0 | 0 | |
| số lần gọi `parse_fn` | **3** | 3 | chỉ dòng 4, 9, 11 |

- **Vì sao chạy 2 vẫn gọi `parse_fn` 3 lần dù sid 1002 bị tắt:** `sid` chỉ biết được sau khi parse, nên rule bị tắt bằng `disabled_sids` vẫn đi qua Parser; Loader chuyển nó thành `disabled` ngay sau đó.
- Đẳng thức `rule_lines == valid + invalid + unsupported + disabled` đúng ở cả hai lần chạy (3 = 3 + 0 + 0 + 0 và 3 = 2 + 0 + 0 + 1); `total_lines == blank + comment + rule_lines` (10 = 3 + 4 + 3).
- Dòng đưa sang Parser có `line_no` 4, 9, 11; dòng nối có nội dung `alert tcp any any -> any 80 (msg:"T01 rule 1002"; content:"POST"; sid:1002;)` (hai nửa nối bằng đúng một dấu cách, bỏ `\`).
- Rule sid 1999 (bị comment) và sid 2001 (file tắt) không xuất hiện ở đâu cả.
- Chạy 2: bản ghi dòng 9 có `status="disabled"`, `reason="disabled:sid"`, `sid=1002`; Repository chỉ còn `[1001, 1003]`.
- `rules_report.jsonl` (chạy bằng `main.py`) có 3 dòng, đều `valid`, `reason: null`, `line` 4, 9, 11; `detections.jsonl` rỗng (gói SYN không khớp rule nào).

## Kết quả thực tế
Chạy `pytest TEST/BT3/T01_rule_loading`: **15 test pass**, mọi giá trị khớp bảng tính tay (không phải sửa kỳ vọng).

- Chạy 1: `total_lines=10, blank=3, comment=4, rule_lines=3, valid=3, invalid=0, unsupported=0, disabled=0, files_failed=0, disabled_files=1`; `parse_fn` giả được gọi đúng 3 lần với `line_no` 4, 9, 11.
- Chạy 2: `valid=2, disabled=1, rule_lines=3`; bản ghi dòng 9 là `disabled / disabled:sid / 1002`; Repository `[1001, 1003]`.
- `main.py` chạy 1: `rules_report.jsonl` 3 dòng `valid`; `events.jsonl` 1 event; `flows.jsonl` 1 flow; `detections.jsonl` rỗng.
- `main.py` chạy 2 (thư mục `variant_disabled_sids/`): `rules_report.jsonl` 3 dòng, dòng 9 là `disabled / disabled:sid / 1002`, hai dòng kia `valid`.
- `input.pcap` dựng lại hai lần cho cùng md5 (`050c352a8513acdfe403b483e4a3b955`).

## Bằng chứng trong thư mục
Cả hai lần chạy đều từ đường chạy thật `main.py` (do `run_case_ids` gọi, các file được test sinh lại mỗi lần chạy, không sửa tay):
- Chạy 1, cạnh `input.pcap`: `rules_report.jsonl`, `events.jsonl`, `flows.jsonl`, `detections.jsonl`.
- Chạy 2, trong `variant_disabled_sids/`: bốn file cùng tên.
- Trường `file` của `rules_report.jsonl` là đường dẫn tương đối so với gốc repo (`TEST/BT3/T01_rule_loading/rules.rules`), nên không chứa đường dẫn riêng của máy chạy.

## Kết luận
**PASS.**

Chạy: `pytest TEST/BT3/T01_rule_loading`.
