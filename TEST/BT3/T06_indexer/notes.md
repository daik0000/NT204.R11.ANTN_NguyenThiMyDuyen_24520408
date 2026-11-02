# T06 – Chọn rule ứng viên bằng chỉ mục

## Mục tiêu
Với mỗi gói, chỉ mục (Indexer) chỉ trả về các rule có thể áp dụng theo **protocol** và **cổng đích**, theo đúng thứ tự rule trong file, nên engine không phải thử toàn bộ rule cho mỗi gói. Rule `<>` còn được đăng ký theo cổng nguồn của rule để không bỏ sót gói đi chiều ngược. Protocol lạ cho kết quả rỗng, không lỗi.

## Input
- `rules.rules`: 7 rule chỉ có header, sid 6001–6007 (rule thứ `n` có sid `6000 + n`):

| # | Rule | sid |
|---|---|---|
| 1 | `tcp any -> 80` | 6001 |
| 2 | `tcp any -> 1:1024` | 6002 |
| 3 | `tcp any -> any` | 6003 |
| 4 | `udp any -> 53` | 6004 |
| 5 | `ip any -> any` | 6005 |
| 6 | `udp any -> 5000:6000` | 6006 |
| 7 | `tcp 443 <> 8443` (cổng nguồn 443, cổng đích 8443) | 6007 |

- Phần 1 (không cần pcap): nạp bằng `run_rules_only`, dựng `RuleRepository` rồi `RuleIndexer` và gọi `candidates(protocol, dst_port)` cho 7 cặp.
- Phần 2 (qua `main.py`): `input.pcap` (do `make_pcap.py` dựng, md5 cố định `e13f532a5f6d047cbbdb3b7059710e0e`), 9 gói: gói 1–7 là 7 cặp của bảng (cổng nguồn `40000 + n`), gói 8 là TCP `443 -> 8443`, gói 9 là TCP `8443 -> 443` (hai chiều của rule 7).
- Cách nạp: bài test chạy `main.py` với `--rules rules.rules`; cấu hình tạm có `engine.rule_files: []` nên không có rule mẫu nào khác bị nạp.

## Kết quả mong đợi (tính tay trước khi chạy)
Chỉ mục chỉ nhìn protocol và cổng đích; rule `<>` còn được đăng ký theo cổng nguồn của rule. Rule 3 (`tcp any`) và rule 5 (`ip any`) áp dụng cho mọi cổng; rule `ip` áp dụng cho cả TCP lẫn UDP.

| Cặp (protocol, cổng đích) | Các rule ứng viên | Lý do ngắn gọn |
|---|---|---|
| tcp/80 | 1, 2, 3, 5 → sid **6001, 6002, 6003, 6005** | 80 là cổng của rule 1, nằm trong 1:1024 của rule 2; 3 và 5 là "any" |
| tcp/443 | 2, 3, 5, 7 → **6002, 6003, 6005, 6007** | 443 trong 1:1024; rule 7 vì 443 là **cổng nguồn** của nó (`<>`) |
| tcp/8443 | 3, 5, 7 → **6003, 6005, 6007** | 8443 > 1024 nên không có rule 2; rule 7 vì 8443 là cổng đích |
| tcp/2000 | 3, 5 → **6003, 6005** | chỉ 2/7 rule: chứng minh không duyệt toàn bộ |
| udp/53 | 4, 5 → **6004, 6005** | rule 6 không (53 < 5000) |
| udp/5500 | 5, 6 → **6005, 6006** | 5500 ∈ 5000:6000 |
| udp/80 | 5 → **6005** | chỉ rule `ip` |

- Tổng số ứng viên của 7 cặp = 4 + 4 + 3 + 2 + 2 + 2 + 1 = 18 (so với 7 × 7 = 49 nếu duyệt toàn bộ).
- Biên của dải: tcp/1 và tcp/1024 có rule 2, tcp/0 và tcp/1025 không; udp/5000 và udp/6000 có rule 6, udp/4999 và udp/6001 không.
- Protocol lạ (`icmp`, `arp`, rỗng, `None`, `http`) hoặc cổng sai (`-1`, `65536`, `None`, chuỗi) ⇒ `[]`, không lỗi; `TCP` viết hoa cho cùng kết quả như `tcp`.

Phần 2 — qua `main.py` (rule header-only, nên ứng viên nào qua được stage header đều khớp):

| Gói | Cặp | Ứng viên | Rule khớp thật | Ghi chú |
|---|---|---|---|---|
| 1 | tcp/80 | 1, 2, 3, 5 | 1, 2, 3, 5 | |
| 2 | tcp/443 | 2, 3, 5, 7 | 2, 3, 5 | rule 7 bị stage header loại: cổng nguồn 40002 không phải 443/8443 |
| 3 | tcp/8443 | 3, 5, 7 | 3, 5 | rule 7 bị loại: cổng nguồn 40003 |
| 4 | tcp/2000 | 3, 5 | 3, 5 | |
| 5 | udp/53 | 4, 5 | 4, 5 | |
| 6 | udp/5500 | 5, 6 | 5, 6 | |
| 7 | udp/80 | 5 | 5 | |
| 8 | tcp 443 → 8443 | 3, 5, 7 | 3, 5, 7 | rule 7 chiều thuận |
| 9 | tcp 8443 → 443 | 2, 3, 5, 7 | 2, 3, 5, 7 | rule 7 chiều đảo; chỉ là ứng viên vì rule `<>` được đăng ký theo cổng 443 |

- `candidates` = 4 + 4 + 3 + 2 + 2 + 2 + 1 + 3 + 4 = **25** (nếu thử mọi rule trên mọi gói: 9 × 7 = 63).
- `rejected_header` = **2** (rule 7 ở gói 2 và gói 3); `detections` = `matches` = 4 + 3 + 2 + 2 + 2 + 2 + 1 + 3 + 4 = **23**.
- Dòng tóm tắt cuối: `rules(loaded=7, invalid=0, unsupported=0), events_evaluated=9, candidates=25, detections=23`.
- 9 event, 8 flow (gói 8 và 9 cùng một flow).

## Kết quả thực tế
Chạy `pytest TEST/BT3/T06_indexer`: **29 test pass**, mọi giá trị khớp bảng tính tay (không phải sửa kỳ vọng).

- Phần 1: danh sách `sid` của 7 cặp đúng từng phần tử và đúng thứ tự; `tcp/2000` chỉ có 2/7 rule; rule 6007 xuất hiện ở `tcp/443` (cổng nguồn) và `tcp/8443` (cổng đích); protocol lạ và cổng sai cho `[]`; các biên của dải đúng.
- Phần 2: số Detection theo từng gói đúng như bảng; rule 6007 chỉ khớp ở gói 8 và gói 9. Thống kê engine: `candidate_rules=25`, `rejected_header=2`, `matches=23`, `rule_errors=0`; dòng tóm tắt: `events_evaluated=9, candidates=25, detections=23`.
- `rules_report.jsonl`: 7 dòng `valid`; `main.py` exit 0.
- `input.pcap` dựng lại cho cùng md5; chạy hai lần liên tiếp cho output giống hệt từng byte.

## Bằng chứng trong thư mục
- `candidates.jsonl`: kết quả của Phần 1, mỗi dòng một cặp `(protocol, dst_port)` với danh sách `sids` (do bài test sinh ra).
- `rules_report.jsonl`, `events.jsonl`, `flows.jsonl`, `detections.jsonl`: output của `main.py` ở Phần 2 (qua `run_case_ids`).
- Tất cả được sinh lại mỗi lần chạy, không sửa tay; trường `file` của báo cáo là đường dẫn tương đối so với gốc repo.

## Kết luận
**PASS.**

Chạy: `pytest TEST/BT3/T06_indexer`.
