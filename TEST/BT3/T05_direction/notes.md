# T05 – Chiều của rule (`->` và `<>`)

## Mục tiêu
Rule `->` chỉ khớp gói đi đúng chiều từ nguồn tới đích của rule; rule `<>` khớp cả chiều thuận lẫn chiều đảo. Chiều đảo phải đảo **cả cặp (IP, cổng)** cùng lúc: nguồn của gói đối chiếu với đích của rule **và** đích của gói đối chiếu với nguồn của rule.

## Input
- `rules.rules`: 2 rule chỉ có header (không `content`, không option khác), cùng IP và cổng:
  - sid 5001: `alert tcp 10.0.0.5 any -> 192.168.1.20 80`
  - sid 5002: `alert tcp 10.0.0.5 any <> 192.168.1.20 80`
- `input.pcap` (do `make_pcap.py` dựng, md5 cố định `16020cf5b876dc0316e45382d32b9424`), 3 gói TCP:
  1. `10.0.0.5:52133 -> 192.168.1.20:80` (SYN, chiều thuận)
  2. `192.168.1.20:80 -> 10.0.0.5:52133` (SYN/ACK, chiều ngược lại)
  3. `10.9.9.9:52133 -> 192.168.1.20:80` (SYN từ máy khác)
- Biến thể (chạy riêng, thư mục `variant_fixed_ports/`): `variants.rules` có sid 5101 (`->`) và 5102 (`<>`) với **cổng nguồn cố định** `10.0.0.5 52133 ... 192.168.1.20 80`, và `variants.pcap` 4 gói:
  - v1: `10.0.0.5:52133 -> 192.168.1.20:80` (chiều thuận)
  - v2: `192.168.1.20:80 -> 10.0.0.5:52133` (đảo đúng cả IP lẫn cổng)
  - v3: `192.168.1.20:52133 -> 10.0.0.5:80` (chỉ đảo IP, giữ nguyên cổng)
  - v4: `10.0.0.5:80 -> 192.168.1.20:52133` (chỉ đảo cổng, giữ nguyên IP)
- Cách nạp: bài test chạy `main.py` với `--rules`; cấu hình tạm có `engine.rule_files: []` nên không có rule mẫu nào khác bị nạp.

## Kết quả mong đợi (tính tay trước khi chạy)
Chạy chính (`rules.rules` + `input.pcap`):

| Gói | 5001 (`->`) | 5002 (`<>`) | Vì sao |
|---|---|---|---|
| 1 | MATCH | MATCH | đúng chiều thuận của rule |
| 2 | NO MATCH | MATCH | chỉ có chiều đảo: nguồn (192.168.1.20, 80) = đích rule, đích (10.0.0.5, 52133) thuộc nguồn rule (`any` cổng) |
| 3 | NO MATCH | NO MATCH | nguồn 10.9.9.9 không phải 10.0.0.5 ở cả hai chiều |

- 5001 khớp 1 gói, 5002 khớp 2 gói, gói 3 không khớp rule nào ⇒ **tổng 3 Detection**, theo thứ tự `(gói 1, 5001)`, `(gói 1, 5002)`, `(gói 2, 5002)`; mỗi cái `matched = [{"keyword": "header"}]`.
- `flow_direction` (vai trò của bên gửi): gói 1 là `to_server` (SYN đầu tiên, 10.0.0.5 là client), gói 2 là `to_client`; hai gói cùng `flow_id`. Đây khác với chiều của **rule**: gói 2 khớp `<>` ở chiều đảo nhưng vai trò của nó là `to_client`.
- Bộ chỉ mục (protocol + cổng đích; rule `<>` còn được đăng ký theo cổng nguồn của rule): gói 1 (đích 80) có ứng viên 5001, 5002; gói 2 (đích 52133) chỉ có 5002 vì 5001 chỉ được đăng ký ở cổng 80; gói 3 (đích 80) có 5001, 5002. Tổng `candidates = 5`; hai ứng viên của gói 3 trượt ở stage header ⇒ `rejected_header = 2`, `matches = 3`.
- Dòng tóm tắt cuối: `rules(loaded=2, invalid=0, unsupported=0), events_evaluated=3, candidates=5, detections=3`.
- 3 event, 2 flow (gói 1+2 cùng một flow, gói 3 một flow khác).

Biến thể (`variants.rules` + `variants.pcap`), cổng cố định, rule 5101 `->` và 5102 `<>`:

| Gói | 5101 | 5102 | Vì sao |
|---|---|---|---|
| v1 | MATCH | MATCH | chiều thuận |
| v2 | NO MATCH | MATCH | đảo đúng cả cặp (IP, cổng) |
| v3 | NO MATCH | NO MATCH | chỉ đảo IP: (192.168.1.20, 52133) ≠ đích rule (192.168.1.20, **80**); chiều thuận cũng sai IP |
| v4 | NO MATCH | NO MATCH | chỉ đảo cổng: (10.0.0.5, 80) ≠ đích rule (192.168.1.20, 80) vì sai IP; chiều thuận sai cổng |

- 3 Detection: `(v1, 5101)`, `(v1, 5102)`, `(v2, 5102)`; v3 và v4 không có Detection nào.
- `candidates = 6` (v1: 5101, 5102; v2: 5102; v3: 5101, 5102; v4: 5102), `rejected_header = 3` (hai của v3, một của v4), `matches = 3`.
- Dòng tóm tắt: `events_evaluated=4, candidates=6, detections=3`.
- Nếu chiều đảo chỉ đảo IP mà giữ cổng (hoặc ngược lại), v3 hoặc v4 sẽ khớp sai — đây là lỗi mà biến thể này chặn.

## Kết quả thực tế
Chạy `pytest TEST/BT3/T05_direction`: **19 test pass**, mọi giá trị khớp bảng tính tay (không phải sửa kỳ vọng).

- `detections.jsonl`: 3 dòng — `(1, 5001)`, `(1, 5002)`, `(2, 5002)`; gói 2 mang địa chỉ riêng của nó (`192.168.1.20:80 -> 10.0.0.5:52133`), `flow_direction = to_client`; gói 1 là `to_server`; cùng `flow_id`.
- `rules_report.jsonl`: 2 dòng `valid` (sid 5001, 5002); `events.jsonl` 3 event; `flows.jsonl` 2 flow; `main.py` exit 0.
- Dòng tóm tắt: `events_evaluated=3, candidates=5, detections=3`; thống kê engine `rejected_header=2, matches=3, rule_errors=0`.
- Biến thể: `variant_fixed_ports/detections.jsonl` 3 dòng — `(1, 5101)`, `(1, 5102)`, `(2, 5102)`; `candidates=6`, `rejected_header=3`, `matches=3`.
- Hai pcap dựng lại cho cùng md5; chạy hai lần liên tiếp cho output giống hệt từng byte.

## Bằng chứng trong thư mục
- Chạy chính, cạnh `input.pcap`: `rules_report.jsonl`, `events.jsonl`, `flows.jsonl`, `detections.jsonl`.
- Biến thể, trong `variant_fixed_ports/`: bốn file cùng tên.
- Cả hai do `main.py` ghi (qua `run_case_ids`), sinh lại mỗi lần chạy, không sửa tay; trường `file` của báo cáo là đường dẫn tương đối so với gốc repo.

## Kết luận
**PASS.**

Chạy: `pytest TEST/BT3/T05_direction`.
