# T02 – Rule không hợp lệ

## Mục tiêu
Mỗi rule hỏng bị loại với **đúng** mã `reason`, có cảnh báo, không làm dừng chương trình; rule hợp lệ đứng cạnh vẫn hoạt động và vẫn sinh Detection. Kiểm cả quy tắc ưu tiên: rule vừa có lỗi `invalid` vừa có phần `unsupported` thì báo `invalid`.

## Input
- `rules.rules`: 1 dòng comment + 1 rule hợp lệ (sid 2001) + 15 rule, mỗi rule có đúng một lỗi.
- `priority.rules`: 3 rule dùng để kiểm quy tắc ưu tiên (xung đột ở header: protocol, action; và ở option: keyword lạ).
- `input.pcap` (do `make_pcap.py` dựng, md5 cố định `4c23c5d1d05306559bf9502d2c174587`): một gói HTTP `GET /index.html` tới `10.0.0.2:80`, khớp rule 2001.
- Cách nạp: bài test chạy `main.py` với hai tuỳ chọn `--rules`, theo thứ tự `rules.rules` rồi `priority.rules`; `engine.rule_files` trong cấu hình được để trống nên không có rule mẫu nào khác bị nạp.

## Kết quả mong đợi (tính tay từ từng dòng, trước khi chạy)
`rules.rules`:

| Dòng | Lỗi trong rule | `status` | `reason` | `sid` đọc được |
|---|---|---|---|---|
| 1 | (comment) | – | – | – |
| 2 | rule hợp lệ | valid | `null` | 2001 |
| 3 | thiếu `)` | invalid | `invalid:malformed_rule` | `null` |
| 4 | chỉ có header, thiếu `(` | invalid | `invalid:malformed_rule` | `null` |
| 5 | không có `sid` | invalid | `invalid:missing_sid` | `null` |
| 6 | `sid:abc` | invalid | `invalid:bad_sid` | `null` |
| 7 | IP `300.1.1.1` | invalid | `invalid:bad_ip` | 2006 |
| 8 | cổng `70000` (> 65535) | invalid | `invalid:bad_port` | 2007 |
| 9 | dải cổng `100:50` (thấp > cao) | invalid | `invalid:bad_port` | 2008 |
| 10 | chiều `<-` | invalid | `invalid:bad_direction` | 2009 |
| 11 | `content:"|4|"` (số chữ số hex lẻ; dấu gạch đứng được escape thành `\|` trong bảng này, trong file là `|4|`) | invalid | `invalid:bad_option_value:content` | 2010 |
| 12 | `content:"ABCDE"; depth:2` (2 < 5) | invalid | `invalid:depth_lt_pattern` | 2011 |
| 13 | `content:"ABCDE"; ... within:3` (3 < 5) | invalid | `invalid:within_lt_pattern` | 2012 |
| 14 | `offset:0; distance:1` trên cùng content | invalid | `invalid:mixed_absolute_relative` | 2013 |
| 15 | `flags:S` trong rule `udp` | invalid | `invalid:flags_requires_tcp` | 2014 |
| 16 | `flow:to_server,to_client` | invalid | `invalid:conflicting_flow` | 2015 |
| 17 | `sid:2001` lần thứ hai | invalid | `invalid:duplicate_sid` | 2001 |

`priority.rules` (quy tắc: rule vừa có lỗi `invalid` vừa có phần `unsupported` thì báo `invalid`):

| Dòng | Rule | Mong đợi (`reason`) | `sid` | Không được là |
|---|---|---|---|---|
| 1 | `alert icmp ... (msg:"x";)` – protocol `unsupported` nhưng thiếu `sid` | `invalid:missing_sid` | `null` (không có `sid`) | `unsupported:protocol:icmp` |
| 2 | `drop tcp ... -> any 99999 (...)` – action `unsupported` nhưng cổng sai | `invalid:bad_port` | 2018 | `unsupported:action:drop` |
| 3 | `content:"ABCDE"; depth:2; pcre:"/a/"` – keyword `pcre` `unsupported` nhưng `depth` nhỏ hơn pattern | `invalid:depth_lt_pattern` | 2019 | `unsupported:keyword:pcre` |

Ghi chú về `sid`: rule sai cấu trúc hoặc có `sid` thiếu/không phải số thì không đọc được `sid` (`null`); các lỗi còn lại vẫn mang `sid` của rule. Dòng 17 mang sid 2001 vì đó chính là sid bị trùng.

Hệ quả khác:
- Đếm: `rules.rules` có 17 dòng logic = 1 comment + 16 dòng rule (1 valid + 15 invalid); cả hai file: 20 dòng, 19 dòng rule, `valid=1`, `invalid=18`, `unsupported=0`.
- `main.py` thoát với mã 0; chương trình xử lý gói bình thường (1 event, 1 flow).
- `detections.jsonl` có đúng 1 Detection: sid 2001, `packet_id=1`, `protocol=TCP`, `dst_port=80`, `application_protocol=HTTP` (gói là một request HTTP hợp lệ), `matched=[{"keyword":"content","value":"GET","offset":0,"length":3}]`.
- Mỗi rule hỏng có đúng một dòng cảnh báo `rule <file>:<dòng> rejected: <reason>`: 15 + 3 = 18 dòng, không dòng nào cho rule hợp lệ (dòng 2), không dòng nào lặp. `warnings.txt` lưu đúng các dòng này (bỏ tiền tố thời gian và mức log).
- Dòng tóm tắt cuối: `rules(loaded=1, invalid=18, unsupported=0)`, `detections=1`.

## Kết quả thực tế
Chạy `pytest TEST/BT3/T02_invalid_rule`: **31 test pass**, mọi giá trị khớp bảng tính tay (không phải sửa kỳ vọng).

- `rules_report.jsonl`: 19 dòng; dòng 2 của `rules.rules` là `valid`, 15 dòng còn lại của file đó và 3 dòng của `priority.rules` đúng như hai bảng trên.
- `detections.jsonl`: 1 dòng, sid 2001, `packet_id=1`, `application_protocol="HTTP"`, `matched` đúng như trên.
- `events.jsonl`: 1 event, `flows.jsonl`: 1 flow; `main.py` exit 0.
- Cảnh báo: 18 dòng `rejected`, khớp từng cặp (file, dòng, reason), không trùng; `warnings.txt` giống hệt giữa hai lần chạy liên tiếp.
- `run_rules_only` (không cần pcap) cho cùng kết quả phân loại; bộ đếm của `rules.rules`: `total_lines=17, comment=1, blank=0, rule_lines=16, valid=1, invalid=15, unsupported=0`; với cả hai file: `total_lines=20, rule_lines=19, valid=1, invalid=18, unsupported=0`.
- `input.pcap` dựng lại cho cùng md5.

## Bằng chứng trong thư mục
`rules_report.jsonl`, `events.jsonl`, `flows.jsonl`, `detections.jsonl` do `main.py` ghi (qua `run_case_ids`), và `warnings.txt` do bài test sinh từ stderr của lần chạy đó (bỏ tiền tố thời gian để file không đổi giữa các lần chạy). Tất cả được sinh lại mỗi lần chạy, không sửa tay, và giống hệt từng byte giữa hai lần chạy liên tiếp; trường `file` là đường dẫn tương đối so với gốc repo.

## Kết luận
**PASS.**

Chạy: `pytest TEST/BT3/T02_invalid_rule`.
