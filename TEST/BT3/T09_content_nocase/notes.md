# T09 – `content` và `nocase`

## Mục tiêu
`content` mặc định phân biệt hoa/thường; `nocase` bỏ qua chênh lệch hoa/thường (chỉ chữ A–Z); khối hex `|47 45 54|` và dạng trộn chữ với hex `GE|54|` được đổi sang đúng các byte để so khớp. `matched` báo vị trí và độ dài của chỗ khớp, còn `value` là chuỗi viết trong rule.

## Input
- `rules.rules` (sid 9001–9005), tất cả có header `alert tcp any any -> any 80` và chỉ có `content` (không flow, flags hay dsize):

| sid | Option |
|---|---|
| 9001 | `content:"admin"` |
| 9002 | `content:"admin"; nocase;` |
| 9003 | `content:"Admin"` |
| 9004 | `content:"\|47 45 54\|"` |
| 9005 | `content:"GE\|54\|"; nocase;` |

Ghi chú: dấu gạch đứng trong hai dòng 9004 và 9005 được escape thành `\|` chỉ vì bảng markdown; trong `rules.rules` là `|47 45 54|` và `GE|54|` (không có dấu backslash).

- `input.pcap` (do `make_pcap.py` dựng, md5 cố định `9e4117693ebc0b9b118e36443271ed22`): một gói TCP `10.0.0.1:40009 -> 10.0.0.2:80` có payload `GET /Admin HTTP/1.1` (kèm `Host` và dòng trống).
- Biến thể (chạy riêng, thư mục `variant_capitals/`): `variants.pcap` có một gói với payload `GET /ADMIN HTTP/1.1` (đường dẫn viết hoa hết); dùng cùng `rules.rules`.
- Cách nạp: bài test chạy `main.py` với `--rules`; cấu hình tạm có `engine.rule_files: []` nên không có rule mẫu nào khác bị nạp.

## Kết quả mong đợi (tính tay trước khi chạy)
Vị trí trong payload `GET /Admin HTTP/1.1`: `G`=0, `E`=1, `T`=2, dấu cách=3, `/`=4, `Admin` bắt đầu ở 5 (5 byte). `0x47 0x45 0x54` là các byte của `G E T`; `GE|54|` là `G`, `E`, rồi byte `0x54` = `T`, nên cũng là `GET`.

| sid | Pattern (byte) | Gói `…/Admin…` | Offset / length |
|---|---|---|---|
| 9001 | `admin` | **NO MATCH** — payload viết `Admin` (chữ A hoa), không có `nocase` | – |
| 9002 | `admin`, nocase | **MATCH** | 5 / 5 |
| 9003 | `Admin` | **MATCH** — đúng như payload | 5 / 5 |
| 9004 | `GET` | **MATCH** | 0 / 3 |
| 9005 | `GET`, nocase | **MATCH** | 0 / 3 |

⇒ **4 Detection** (9002, 9003, 9004, 9005), theo thứ tự rule. `matched[0].value` là chuỗi viết trong rule: `admin` (dù gói là `Admin`), `Admin`, `|47 45 54|`, `GE|54|`.

Thống kê: mỗi rule chỉ có `content` nên cả 5 rule ứng viên vào stage content: `candidate_rules = 5`, `content_evaluations = 5`, `rejected_content = 1` (9001), `matches = 4`, các `rejected_header/flow/packet = 0`. Tóm tắt cuối: `rules(loaded=5, invalid=0, unsupported=0), events_evaluated=1, candidates=5, detections=4`.

Biến thể — payload `GET /ADMIN HTTP/1.1` (`ADMIN` ở 5):

| sid | Kết quả | Vì sao |
|---|---|---|
| 9001 | NO MATCH | `admin` ≠ `ADMIN`, phân biệt hoa/thường |
| 9002 | **MATCH** (5 / 5) | `nocase` |
| 9003 | NO MATCH | `Admin` ≠ `ADMIN` |
| 9004 | **MATCH** (0 / 3) | chỉ khớp phần `GET` |
| 9005 | **MATCH** (0 / 3) | chỉ khớp phần `GET` |

⇒ **3 Detection** (9002, 9004, 9005); `rejected_content = 2` (9001, 9003), `matches = 3`; tóm tắt: `events_evaluated=1, candidates=5, detections=3`.

## Kết quả thực tế
Chạy `pytest TEST/BT3/T09_content_nocase`: **21 test pass**, mọi giá trị khớp bảng tính tay (không phải sửa kỳ vọng).

- Chạy chính: `detections.jsonl` có 4 dòng (9002, 9003, 9004, 9005) với `matched` đúng offset/length và `value` như bảng; không có 9001. Thống kê: `candidate_rules=5, content_evaluations=5, rejected_content=1, matches=4, rule_errors=0`.
- Pattern đã biên dịch: 9004 và 9005 đều ra `b"GET"` (`[0x47, 0x45, 0x54]`); 9005 có `nocase`.
- Tìm trực tiếp trên payload (không qua `main.py`): `admin` không có, `admin` với `nocase` ở 5, `Admin` ở 5, `GET` ở 0, `get` (không `nocase`) không có; `match_contents` cho cùng kết quả như Detection.
- Biến thể: `variant_capitals/detections.jsonl` có 3 dòng (9002, 9004, 9005); `rejected_content=2`, `matches=3`.
- `rules_report.jsonl`: 5 dòng `valid`; `main.py` exit 0; hai pcap dựng lại cho cùng md5; output hai lần chạy liên tiếp giống hệt từng byte.

## Bằng chứng trong thư mục
- Chạy chính, cạnh `input.pcap`: `rules_report.jsonl`, `events.jsonl`, `flows.jsonl`, `detections.jsonl`.
- Biến thể, trong `variant_capitals/`: bốn file cùng tên.
- Do `main.py` ghi (qua `run_case_ids`), sinh lại mỗi lần chạy, không sửa tay; trường `file` là đường dẫn tương đối so với gốc repo.

## Kết luận
**PASS.**

Chạy: `pytest TEST/BT3/T09_content_nocase`.
