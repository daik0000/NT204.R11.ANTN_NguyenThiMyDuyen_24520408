# T12 – `flags` và `dsize`

## Mục tiêu
`flags` so cờ TCP của gói theo bốn chế độ: chính xác (`S`), tất cả các cờ này được đặt và cờ khác tuỳ ý (`A+`), ít nhất một trong các cờ (`SF*`), không cờ nào (`!S`); `flags:0` là không có cờ nào. `dsize` so độ dài payload thật (`N`, `<N`, `>N`, `N<>M` có cả hai đầu). Điểm dễ sai nhất: `flags:A` (chính xác) **không** khớp `PSH/ACK` hay `FIN/ACK`, khác với `flags:A+`. Gói UDP không có cờ nên không bao giờ khớp rule dùng `flags`.

## Input
- `rules.rules` (sid 12001–12011), tất cả có header `alert tcp any any <> any 9003` (hai chiều, để SYN/ACK của server cũng qua header) và không có `content`, nên chỉ `flags`/`dsize` quyết định:

| sid | Option |
|---|---|
| 12001 | `flags:S` |
| 12002 | `flags:SA` |
| 12003 | `flags:A` |
| 12004 | `flags:A+` |
| 12005 | `flags:SF*` |
| 12006 | `flags:PA; dsize:10` |
| 12007 | `dsize:0` |
| 12008 | `dsize:<5` |
| 12009 | `dsize:10` |
| 12010 | `dsize:>0` |
| 12011 | `dsize:5<>15` |

- `input.pcap` (do `make_pcap.py` dựng, md5 cố định `22f3ad156f3c8b7e61655f1d60af6051`): phiên TCP tới cổng 9003 (không có parser nên payload là byte thô), 5 gói: p1 SYN, p2 SYN/ACK, p3 ACK, p4 PSH/ACK mang payload 10 byte `0123456789`, p5 FIN/ACK; các gói còn lại không có payload.
- Biến thể (chạy riêng, thư mục `variant_udp_and_modifiers/`): `variants.rules` (sid 12101–12110) và `variants.pcap` gồm 5 gói TCP như trên cộng p6, một datagram UDP tới cổng 9003 mang cùng 10 byte.
- Cách nạp: bài test chạy `main.py` với `--rules`; cấu hình tạm có `engine.rule_files: []` nên không có rule mẫu nào khác bị nạp.

## Kết quả mong đợi (tính tay trước khi chạy)

| sid | Ý nghĩa | Gói khớp |
|---|---|---|
| 12001 `flags:S` | đúng SYN | p1 |
| 12002 `flags:SA` | đúng SYN+ACK | p2 |
| 12003 `flags:A` | đúng ACK, **không** phải PSH/ACK hay FIN/ACK | p3 |
| 12004 `flags:A+` | ACK được đặt, cờ khác tuỳ ý | p2, p3, p4, p5 |
| 12005 `flags:SF*` | SYN hoặc FIN được đặt | p1, p2, p5 |
| 12006 `flags:PA; dsize:10` | đúng PSH+ACK và đúng 10 byte | p4 |
| 12007 `dsize:0` | payload rỗng | p1, p2, p3, p5 |
| 12008 `dsize:<5` | dưới 5 byte | p1, p2, p3, p5 |
| 12009 `dsize:10` | đúng 10 byte | p4 |
| 12010 `dsize:>0` | có payload | p4 |
| 12011 `dsize:5<>15` | từ 5 đến 15 byte, tính cả hai đầu | p4 |

- Số Detection: 1 + 1 + 1 + 4 + 3 + 1 + 4 + 4 + 1 + 1 + 1 = **22**, theo thứ tự gói rồi thứ tự rule trong cùng gói. Mỗi Detection có `matched = [{"keyword": "header"}]` (rule không có `content`).
- Cả 11 rule đều là ứng viên của cả 5 gói (header `<>` với cổng nguồn `any`) ⇒ `candidate_rules = 11 × 5 = 55`; không rule nào trượt ở header hay flow; 33 ứng viên không bắn trượt ở stage **packet**; không có stage content. Thống kê: `rejected_header = 0, rejected_flow = 0, rejected_packet = 33, content_evaluations = 0, matches = 22`.
- Tóm tắt cuối: `rules(loaded=11, invalid=0, unsupported=0), events_evaluated=5, candidates=55, detections=22`.

Biến thể (`variants.rules`, gói p1–p5 như trên và p6 UDP 10 byte):

| sid | Rule | Gói khớp | Ghi chú |
|---|---|---|---|
| 12101 | `alert ip ... flags:S` | p1 | rule `ip` áp dụng cho TCP; gói UDP không có cờ nên không khớp |
| 12102 | `alert udp ... flags:S` | – | **invalid** (`invalid:flags_requires_tcp`), rule không được nạp |
| 12103 | `alert udp ... dsize:10` | p6 | `dsize` dùng được cho UDP |
| 12104 | `alert ip ... flags:0` (không cờ nào) | – | mọi gói TCP đều có cờ; cờ của gói UDP là không xác định |
| 12105 | `alert tcp ... flags:!S` | p3, p4, p5 | p2 SYN/ACK có SYN nên bị loại |
| 12106 | `alert tcp ... flags:FA` | p5 | đúng FIN+ACK |
| 12107 | `alert tcp ... flags:PA+` | p4 | PSH và ACK cùng được đặt |
| 12108 | `alert tcp ... flags:SA*` | p1, p2, p3, p4, p5 | có SYN hoặc ACK |
| 12109 | `alert tcp ... dsize:>9; flags:A+` | p4 | ACK được đặt và hơn 9 byte |
| 12110 | `alert ip ... dsize:10` | p4, p6 | rule `ip` áp dụng cho cả TCP lẫn UDP |

⇒ 1 + 1 + 0 + 3 + 1 + 1 + 5 + 1 + 2 = **15 Detection** (12102 bị loại). Ứng viên: mỗi gói TCP có 5 rule `tcp` + 3 rule `ip` = 8 (5 gói ⇒ 40), gói UDP có 1 rule `udp` + 3 rule `ip` = 4 ⇒ `candidate_rules = 44`, `rejected_packet = 44 − 15 = 29`. Báo cáo: 9 rule `valid`, 1 `invalid`, và đúng 1 dòng cảnh báo. Tóm tắt: `rules(loaded=9, invalid=1, unsupported=0), events_evaluated=6, candidates=44, detections=15`.

## Kết quả thực tế
Chạy `pytest TEST/BT3/T12_flags_dsize`: **34 test pass**, mọi giá trị khớp bảng tính tay (không phải sửa kỳ vọng).

- `detections.jsonl`: 22 dòng; danh sách gói của từng rule đúng như bảng (ví dụ 12003 ra `[3]`, 12004 ra `[2, 3, 4, 5]`). Thống kê: `candidate_rules=55, rejected_packet=33, matches=22, rule_errors=0`.
- Các gói đúng như giả định: cờ `[SYN]`, `[SYN, ACK]`, `[ACK]`, `[PSH, ACK]`, `[FIN, ACK]`; payload 0, 0, 0, 10, 0 byte.
- Gọi trực tiếp `match_flags` và `match_dsize` trên các gói đọc từ pcap cho cùng tập gói như bảng với cả 11 rule.
- Biến thể: `variant_udp_and_modifiers/detections.jsonl` có 15 dòng đúng như bảng; gói UDP chỉ khớp hai rule `dsize` (12103, 12110); `candidates=44, rejected_packet=29, matches=15`; 12102 là `invalid:flags_requires_tcp`.
- `rules_report.jsonl`: 11 dòng `valid`; `main.py` exit 0; hai pcap dựng lại cho cùng md5; output hai lần chạy liên tiếp giống hệt từng byte.

## Bằng chứng trong thư mục
- Chạy chính, cạnh `input.pcap`: `rules_report.jsonl`, `events.jsonl`, `flows.jsonl`, `detections.jsonl`.
- Biến thể, trong `variant_udp_and_modifiers/`: bốn file cùng tên.
- Do `main.py` ghi (qua `run_case_ids`), sinh lại mỗi lần chạy, không sửa tay; trường `file` là đường dẫn tương đối so với gốc repo.

## Kết luận
**PASS.**

Chạy: `pytest TEST/BT3/T12_flags_dsize`.
