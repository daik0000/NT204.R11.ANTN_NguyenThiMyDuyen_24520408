# T07 – Gói bị loại ở header không bao giờ tới bước tìm `content`

## Mục tiêu
Chứng minh bằng số liệu rằng các bước rẻ chạy trước bước đắt: gói không khớp header (hoặc không được chỉ mục chọn làm ứng viên) thì rule bị loại **trước** khi tìm `content`. Bằng chứng là bộ đếm `content_evaluations` chỉ tăng cho gói thật sự vào bước content.

## Input
- `rules.rules`: 1 rule có `content`:
  `alert tcp 10.0.0.5 any -> 192.168.1.20 80 (msg:"T07 GET from 10.0.0.5 to 192.168.1.20:80"; content:"GET"; sid:7001;)`
- `input.pcap` (do `make_pcap.py` dựng, md5 cố định `bef138fafa30d7c98d3c9af9c87a979e`), 3 gói TCP, **cả ba cùng mang payload `GET / HTTP/1.1`** (nên `content` sẽ khớp cả ba nếu được tìm):
  - (a) `10.0.0.5:52133 -> 192.168.1.20:80`: đúng 5-tuple của rule
  - (b) `10.0.0.5:52134 -> 10.9.9.9:80`: IP đích khác, cổng 80
  - (c) `10.0.0.5:52135 -> 192.168.1.20:8080`: cổng đích 8080
- Biến thể (chạy riêng, thư mục `variant_other_mismatches/`): `variants.pcap` có 4 gói cùng payload, mỗi gói lệch header theo một cách khác:
  - (d) `10.9.9.9:52136 -> 192.168.1.20:80`: IP nguồn khác
  - (e) UDP `10.0.0.5:52137 -> 192.168.1.20:80`: UDP thay vì TCP
  - (f) `192.168.1.20:80 -> 10.0.0.5:52138`: chiều trả lời
  - (g) `10.0.0.5:52139 -> 192.168.1.21:80`: IP đích kề bên (`.21` thay vì `.20`)
- Cách nạp: bài test chạy `main.py` với `--rules rules.rules`; cấu hình tạm có `engine.rule_files: []` nên không có rule mẫu nào khác bị nạp.

## Kết quả mong đợi (tính tay trước khi chạy)
Rule được chỉ mục theo protocol `tcp` và cổng đích 80, nên chỉ gói TCP tới cổng 80 mới là ứng viên.

| Gói | Ứng viên? | Header | `content` được tìm? | Kết quả |
|---|---|---|---|---|
| (a) | có (tcp, đích 80) | đạt | **có** | **Detection** (`GET` ở offset 0) |
| (b) | có (tcp, đích 80) | **trượt** (IP đích) | không | `failed_stage = "header"` |
| (c) | **không** (cổng đích 8080 ≠ 80) | – | không | không phải ứng viên |

Thống kê (chạy chính): `candidate_rules = 2` (gói a và b; gói c = 0 ứng viên), `rules_rejected_header = 1` (gói b), **`content_evaluations = 1`** (chỉ gói a), `matches = 1`, `rejected_flow = rejected_packet = rejected_content = rule_errors = 0`; dòng tóm tắt cuối: `events_evaluated=3, candidates=2, detections=1`. Nếu gói c được thử trực tiếp thì cũng trượt header (cổng đích 8080), nên việc chỉ mục loại nó trước là nhất quán.

Biến thể:

| Gói | Ứng viên? | Header | Kết quả |
|---|---|---|---|
| (d) | có | trượt (IP nguồn) | không Detection |
| (e) | không (rule là `tcp`) | – | không phải ứng viên |
| (f) | không (cổng đích 52138) | – | không phải ứng viên |
| (g) | có | trượt (IP đích `.21`) | không Detection |

⇒ `candidate_rules = 2`, `rules_rejected_header = 2`, **`content_evaluations = 0`**, `matches = 0`, không có Detection nào, mặc dù `content:"GET"` khớp cả 4 gói. Dòng tóm tắt: `events_evaluated=4, candidates=2, detections=0`. Thử trực tiếp từng gói với rule thì đều `failed_stage = "header"` và `content_fn` không được gọi lần nào.

## Kết quả thực tế
Chạy `pytest TEST/BT3/T07_header_reject`: **13 test pass**, mọi giá trị khớp bảng tính tay (không phải sửa kỳ vọng).

- Chạy chính: `detections.jsonl` có 1 dòng (gói 1, sid 7001, `matched` = `GET` offset 0 length 3). Thống kê: `candidate_rules=2, rejected_header=1, content_evaluations=1, matches=1, rule_errors=0`; tóm tắt `events_evaluated=3, candidates=2, detections=1`.
- Từng gói qua `match_rule` thật: gói a `matched=True`; gói b `failed_stage="header"`, `matches=[]`; gói c cũng `failed_stage="header"`. `content_fn` giả chỉ được gọi cho gói 1; `content_evaluations` là 1 cho gói a và 0 cho gói b.
- Chỉ mục: rule chỉ được đề nghị cho gói a và b, không cho gói c.
- `content` khớp cả ba gói khi tìm trực tiếp (`match_contents`), nên việc gói b và c không có Detection chỉ do header (hoặc chỉ mục).
- Biến thể: không có Detection, `candidate_rules=2`, `rejected_header=2`, `content_evaluations=0`; mỗi gói `failed_stage="header"` và `content_fn` không được gọi.
- `rules_report.jsonl`: 1 dòng `valid`; `main.py` exit 0; hai pcap dựng lại cho cùng md5; output hai lần chạy liên tiếp giống hệt từng byte.

## Bằng chứng trong thư mục
- Chạy chính, cạnh `input.pcap`: `rules_report.jsonl`, `events.jsonl`, `flows.jsonl`, `detections.jsonl`.
- Biến thể, trong `variant_other_mismatches/`: bốn file cùng tên (`detections.jsonl` rỗng).
- Do `main.py` ghi (qua `run_case_ids`), sinh lại mỗi lần chạy, không sửa tay; trường `file` là đường dẫn tương đối so với gốc repo.

## Kết luận
**PASS.**

Chạy: `pytest TEST/BT3/T07_header_reject`.
