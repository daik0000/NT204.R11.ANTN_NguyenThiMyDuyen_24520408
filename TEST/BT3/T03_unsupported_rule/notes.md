# T03 – Rule ngoài phạm vi hỗ trợ

## Mục tiêu
Rule đúng cú pháp Snort nhưng nằm ngoài phạm vi hỗ trợ phải được báo `unsupported` với đúng `reason`, kèm một dòng cảnh báo, **không bị bỏ qua âm thầm** (nếu bỏ qua phần không hỗ trợ thì rule sẽ khớp rộng hơn ý tác giả) và không làm dừng chương trình. Hai keyword chỉ để lưu (`reference`, `metadata`) vẫn là rule hợp lệ.

## Input
- `rules.rules`: 1 dòng comment + 16 dòng rule: 2 rule hợp lệ (sid 3001, 3015) và 14 rule ngoài phạm vi, mỗi rule một lý do.
- `input.pcap` (do `make_pcap.py` dựng, md5 cố định `ab7c87753235e3c2eecbb1ffa24fcb66`): một gói HTTP `GET /index.html HTTP/1.1` tới `10.0.0.2:80`. Với 13 trong 14 rule ngoài phạm vi (trừ rule `icmp`), gói này sẽ khớp nếu phần không hỗ trợ bị bỏ qua (xem cột "Khớp nếu bỏ phần lạ?" bên dưới), nên việc không có Detection cho chúng là bằng chứng thật.
- Cách nạp: bài test chạy `main.py` với `--rules rules.rules`; cấu hình tạm có `engine.rule_files: []` (danh sách rỗng, không phải thiếu khoá — thiếu khoá thì engine nạp `config/rules/local.rules` mặc định) nên không có rule mẫu nào khác bị nạp.

## Kết quả mong đợi (tính tay từ từng dòng, trước khi chạy)
Gói trong `input.pcap`: TCP `10.0.0.1:40003 -> 10.0.0.2:80`, cờ PSH+ACK, payload `GET /index.html HTTP/1.1...`.
Cột "Khớp nếu bỏ phần lạ?" là điều kiện để câu "rule không sinh Detection" có giá trị chứng minh: chỉ khi rule **sẽ khớp** nếu phần không hỗ trợ bị bỏ qua thì việc không có Detection mới chứng tỏ engine thật sự từ chối rule.

| Dòng | Rule (phần đáng chú ý) | `status` | `reason` | `sid` | Khớp nếu bỏ phần lạ? |
|---|---|---|---|---|---|
| 1 | (comment) | – | – | – | – |
| 2 | `content:"GET"` | valid | `null` | 3001 | (hợp lệ, khớp) |
| 3 | `pcre:"/etc/passwd/i"` | unsupported | `unsupported:keyword:pcre` | 3002 | Có: còn `content:"GET"` |
| 4 | `byte_test:2,>,5,0` | unsupported | `unsupported:keyword:byte_test` | 3003 | Có: còn `content:"GET"` |
| 5 | `flowbits:set,x` | unsupported | `unsupported:keyword:flowbits` | 3004 | Có: còn `content:"GET"` |
| 6 | `threshold:type limit, track by_src, count 1, seconds 60` | unsupported | `unsupported:keyword:threshold` | 3005 | Có: còn `content:"GET"` |
| 7 | `http_uri` (sau `content`) | unsupported | `unsupported:keyword:http_uri` | 3006 | Có: còn `content:"GET"` |
| 8 | `content:!"x"` | unsupported | `unsupported:content_negation` | 3007 | Có: bỏ phủ định thì còn rule chỉ có header, khớp |
| 9 | `alert icmp ...` | unsupported | `unsupported:protocol:icmp` | 3008 | **Không**: gói là TCP, rule `icmp` không thể khớp trong mọi trường hợp — dòng này không có bằng chứng phủ định từ gói |
| 10 | `drop tcp ...` | unsupported | `unsupported:action:drop` | 3009 | Có: coi `drop` như `alert`, `content:"GET"` khớp |
| 11 | IP nguồn `$HOME_NET` | unsupported | `unsupported:ip_syntax` | 3010 | Có: biến đọc như `any` |
| 12 | IP nguồn `[10.0.0.1,10.0.0.2]` | unsupported | `unsupported:ip_syntax` | 3011 | Có: bỏ danh sách thành `any` (nguồn 10.0.0.1 cũng nằm trong danh sách) |
| 13 | IP nguồn `!10.0.0.1` | unsupported | `unsupported:ip_syntax` | 3012 | Có nếu bỏ ràng buộc địa chỉ thành `any` (đọc đúng nghĩa `!` thì không khớp vì nguồn đúng là 10.0.0.1) |
| 14 | cổng đích `[80,443]` | unsupported | `unsupported:port_syntax` | 3013 | Có: bỏ danh sách thành `any` (cổng 80 cũng nằm trong danh sách) |
| 15 | `flow:stateless` | unsupported | `unsupported:flow_option:stateless` | 3014 | Có: bỏ option thì còn `content:"GET"` |
| 16 | `reference:url,example.com/t03; metadata:service http` | **valid** | `null` | 3015 | (hợp lệ, khớp `content:"HTTP"`) |
| 17 | `flags:PA,12` (có mặt nạ) | unsupported | `unsupported:flags_mask` | 3016 | Có: bỏ mặt nạ còn `flags:PA` và gói là PSH+ACK. (Dùng `PA` thay vì `SA` để phép thử có ý nghĩa: `flags:SA` không khớp gói PSH+ACK dù mặt nạ bị bỏ.) |

Mọi rule đều đúng cú pháp nên `sid` luôn đọc được; không có rule nào `invalid`.

Hệ quả:
- Đếm: 17 dòng logic = 1 comment + 16 dòng rule; `valid=2`, `unsupported=14`, `invalid=0`, `disabled=0`.
- `main.py` thoát với mã 0; xử lý gói bình thường (1 event, 1 flow).
- `detections.jsonl` có đúng 2 Detection, theo thứ tự rule: sid 3001 (`matched` = `GET`, offset 0, length 3) và sid 3015 (`matched` = `HTTP`, offset 16, length 4; `"GET /index.html "` dài 16 byte). Cả hai `packet_id=1`, `protocol=TCP`, `dst_port=80`, `application_protocol=HTTP`.
- **Không rule `unsupported` nào sinh Detection.** Câu này có giá trị chứng minh với 13 dòng ghi "Có" ở bảng trên (dòng 3–8, 10–15, 17); dòng 9 (`icmp`) là ca không có bằng chứng phủ định từ gói, chỉ kiểm được `reason`.
- Mỗi rule ngoài phạm vi có đúng một dòng cảnh báo `rule <file>:<dòng> rejected: <reason>`: 14 dòng, không dòng nào cho rule hợp lệ (dòng 2 và 16), không dòng nào lặp. `warnings.txt` lưu đúng các dòng này (bỏ tiền tố thời gian và mức log).
- Dòng tóm tắt cuối: `rules(loaded=2, invalid=0, unsupported=14)`, `detections=2`.
- Rule dòng 16 giữ `reference` và `metadata` như option chỉ để lưu (`passive_options`), không ảnh hưởng việc khớp.

## Kết quả thực tế
Chạy `pytest TEST/BT3/T03_unsupported_rule`: **29 test pass**, mọi giá trị khớp bảng tính tay (không phải sửa kỳ vọng).

- `rules_report.jsonl`: 16 dòng; dòng 2 và 16 là `valid`, 14 dòng còn lại là `unsupported` với đúng `reason` và `sid` như bảng.
- `detections.jsonl`: 2 dòng, sid 3001 và 3015 với `matched` như trên; không có sid nào khác.
- `events.jsonl`: 1 event; `flows.jsonl`: 1 flow; `main.py` exit 0.
- `warnings.txt`: 14 dòng, khớp từng cặp (file, dòng, reason); giống hệt từng byte giữa hai lần chạy liên tiếp (cũng như `rules_report.jsonl`, `detections.jsonl`, `events.jsonl`, `flows.jsonl`).
- `run_rules_only` (không cần pcap) phân loại giống hệt; bộ đếm: `total_lines=17, comment=1, blank=0, rule_lines=16, valid=2, invalid=0, unsupported=14, disabled=0`.
- Phép thử cho cột "Khớp nếu bỏ phần lạ?": test viết lại 13 rule theo cách "bỏ phần lạ" (xoá option, đổi `drop` thành `alert`, đổi biến/danh sách thành `any`, bỏ mặt nạ) rồi chạy cùng gói trong thư mục tạm: cả 13 rule đều là rule hợp lệ và cả 13 đều sinh Detection, đúng thứ tự (sid 3002–3007, 3009–3014, 3016).
- `input.pcap` dựng lại cho cùng md5.

## Bằng chứng trong thư mục
`rules_report.jsonl`, `events.jsonl`, `flows.jsonl`, `detections.jsonl` do `main.py` ghi (qua `run_case_ids`), và `warnings.txt` do bài test sinh từ stderr của lần chạy đó. Tất cả được sinh lại mỗi lần chạy, không sửa tay; trường `file` là đường dẫn tương đối so với gốc repo.

## Kết luận
**PASS.**

Chạy: `pytest TEST/BT3/T03_unsupported_rule`.
