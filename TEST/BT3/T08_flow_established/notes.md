# T08 – `flow`: `to_server`, `to_client`, `established`

## Mục tiêu
Kiểm tra điều kiện `flow:` của rule dựa trên **vai trò của bên gửi gói hiện tại** (`to_server`/`to_client`) và **trạng thái sau gói đó** (`established`/`not_established`), kể cả khi flow bắt giữa chừng hoặc bắt từ phía server. Điều dễ sai nhất: nhầm `direction = forward` (do `endpoint_a` gửi) với `to_server`.

## Input
- `rules.rules` (sid 8001–8006): các rule TCP có header `tcp any any -> any any` nên chỉ phần `flow`/`flags`/`content` quyết định kết quả:

| sid | Option |
|---|---|
| 8001 | `flow:to_server,established; content:"GET"` |
| 8002 | `flow:to_client,established; content:"HTTP/1.1 200"` |
| 8003 | `flow:to_server,not_established; flags:S` |
| 8004 | `flow:to_client,not_established; flags:SA` |
| 8005 | `flow:to_client,established; content:"GET"` (kiểm chứng sai chiều: `GET` không bao giờ gửi tới client) |
| 8006 | `alert udp any any <> any 53; flow:not_established` (dùng `<>` để header khớp cả gói response; nếu response không khớp thì lý do là `established`, không phải header) |

- `input.pcap` (do `make_pcap.py` dựng, md5 cố định `1933cf75e8b1e6e480703bf7dec594ef`), 9 gói:
  - Flow 1 (đủ phiên, `10.0.0.1:40101 <-> 10.0.0.2:80`): p1 SYN, p2 SYN/ACK, p3 ACK (không payload), p4 `GET /`, p5 `HTTP/1.1 200 OK`.
  - Flow 2 (**giữa chừng**, `10.0.0.3:40102`): p6 chỉ có `GET /`, không có bắt tay.
  - Flow 3 (**giữa chừng, bắt từ phía server**, client `10.0.0.4:40103`): p7 là `HTTP/1.1 200 OK` từ cổng 80 — gói đầu của flow, nên `endpoint_a` là server.
  - Flow UDP (DNS, `10.0.0.1:5353 <-> 10.0.0.2:53`): p8 query, p9 response.
- Biến thể (chạy riêng, thư mục `variant_close_and_reset/`): `variants.rules` (8101–8103) và `variants.pcap` 10 gói — flow X: SYN, SYN/ACK, ACK, FIN/ACK từ client, FIN/ACK từ server, ACK muộn; flow Y: SYN, SYN/ACK, ACK, RST/ACK từ server.
- Cách nạp: bài test chạy `main.py` với `--rules`; cấu hình tạm có `engine.rule_files: []` nên không có rule mẫu nào khác bị nạp. Cổng 80 và 53 nằm trong `ports` của cấu hình nên dùng để suy ra vai trò khi flow bắt giữa chừng.

## Kết quả mong đợi (tính tay trước khi chạy)
Trạng thái flow **sau** gói hiện tại và vai trò của bên gửi:

| Gói | Mô tả | Trạng thái sau gói | Vai trò | Rule khớp |
|---|---|---|---|---|
| p1 | SYN (flow 1) | HANDSHAKE (chưa established) | `to_server` | **8003** |
| p2 | SYN/ACK | HANDSHAKE | `to_client` | **8004** |
| p3 | ACK thuần, payload rỗng | ESTABLISHED | `to_server` | không rule nào (8001 cần `content:"GET"` mà payload rỗng) |
| p4 | `GET /` | ESTABLISHED | `to_server` | **8001** (8005 sai vai trò) |
| p5 | `HTTP/1.1 200 OK` | ESTABLISHED | `to_client` | **8002** (8005 đúng vai trò nhưng không có `GET`) |
| p6 | `GET /`, flow giữa chừng | ESTABLISHED (flow bắt giữa chừng), vai trò suy từ cổng 80 | `to_server` | **8001** |
| p7 | `200 OK`, flow giữa chừng bắt từ phía server | ESTABLISHED | **`direction = forward` nhưng vai trò `to_client`** | **8002** |
| p8 | DNS query | chưa có gói chiều ngược ⇒ not_established | `to_server` | **8006** |
| p9 | DNS response | có gói chiều ngược (chính nó) ⇒ established | `to_client` | không rule nào (8006 cần `not_established`) |

- Tổng theo sid: **8001 = 2, 8002 = 2, 8003 = 1, 8004 = 1, 8005 = 0, 8006 = 1** ⇒ 7 Detection. 8005 không bao giờ khớp.
- p7 chứng minh không nhầm `direction` với client/server: `events.jsonl` ghi `direction = "forward"` nhưng Detection có `flow_direction = "to_client"`.
- Flow 2 và flow 3 có `midstream = true`; flow 3 có `endpoint_a = 10.0.0.2:80` (server).
- Thống kê: mỗi gói TCP (7 gói) có 5 rule TCP làm ứng viên, mỗi gói UDP (2 gói) có 1 ⇒ `candidate_rules = 37`. `rejected_flow`: p1 4, p2 4, p3 4, p4 4, p5 3, p6 4, p7 3, p8 0, p9 1 = **27**. `rejected_header = rejected_packet = 0`. Stage content có 7 lần chạy xong: p3 (8001), p4 (8001), p5 (8002, 8005), p6 (8001), p7 (8002, 8005) ⇒ `content_evaluations = 7`, trong đó 3 lần không khớp (p3 8001, p5 8005, p7 8005) ⇒ `rejected_content = 3`. `matches = 7` (3 rule không có content: 8003, 8004, 8006; và 4 rule có content). Kiểm tra: 37 = 27 + 3 + 7.
- Dòng tóm tắt cuối: `rules(loaded=6, invalid=0, unsupported=0), events_evaluated=9, candidates=37, detections=7`.
- 9 event, 4 flow.

Biến thể (`variants.rules`: 8101 `flow:established; flags:FA`, 8102 `flow:not_established; flags:RA`, 8103 `flow:from_client,established; flags:A`):

| Gói | Mô tả | Trạng thái sau gói | Rule khớp |
|---|---|---|---|
| 1, 2 | SYN, SYN/ACK (flow X) | HANDSHAKE | không |
| 3 | ACK | ESTABLISHED | 8103 |
| 4 | FIN/ACK từ client | CLOSING (vẫn tính established) | 8101 |
| 5 | FIN/ACK từ server | CLOSED (vẫn established) | 8101 |
| 6 | ACK muộn từ client | CLOSED (không đổi) | 8103 |
| 7, 8 | SYN, SYN/ACK (flow Y) | HANDSHAKE | không |
| 9 | ACK | ESTABLISHED | 8103 |
| 10 | RST/ACK từ server | **RESET (not_established)** | 8102 |

⇒ 6 Detection: `(3, 8103), (4, 8101), (5, 8101), (6, 8103), (9, 8103), (10, 8102)`. Thống kê: `candidates = 30`, `rejected_flow = 16` (8101: 5, 8102: 5, 8103: 6), `rejected_packet = 8` (3 + 4 + 1), `matches = 6`, `content_evaluations = 0`. Gói RST/ACK chính nó là `not_established` vì trạng thái sau gói là RESET (giới hạn đã ghi trong README); `from_client` là tên khác của `to_server`.

## Kết quả thực tế
Chạy `pytest TEST/BT3/T08_flow_established`: **19 test pass**, mọi giá trị khớp bảng tính tay (không phải sửa kỳ vọng).

- `detections.jsonl`: 7 dòng — p1 8003, p2 8004, p4 8001, p5 8002, p6 8001, p7 8002, p8 8006; `flow_direction` đúng như bảng; không có sid 8005.
- p7: `events.jsonl` có `direction = forward`, `flow_state = ESTABLISHED`; Detection có `flow_direction = to_client`. Cả hai flow giữa chừng có `midstream = true`.
- Qua `match_rule` thật: 8005 trên p4 trượt ở stage **flow** (header đạt, `content:"GET"` có trong gói, chỉ sai vai trò `to_server`); 8005 trên p5 qua flow rồi trượt ở **content**; 8006 trên p9 trượt ở **flow** (header `<>` chấp nhận gói trả lời), còn trên p8 khớp.
- Thống kê: `candidate_rules=37, rejected_header=0, rejected_flow=27, rejected_packet=0, content_evaluations=7, rejected_content=3, matches=7, rule_errors=0`.
- Biến thể: trạng thái các gói của flow X là HANDSHAKE, HANDSHAKE, ESTABLISHED, CLOSING, CLOSED, CLOSED; gói 10 là RESET; 6 Detection như bảng; `candidates=30, rejected_flow=16, rejected_packet=8, matches=6`.
- `rules_report.jsonl`: 6 dòng `valid`; `main.py` exit 0; hai pcap dựng lại cho cùng md5; output hai lần chạy liên tiếp giống hệt từng byte.

## Bằng chứng trong thư mục
- Chạy chính, cạnh `input.pcap`: `rules_report.jsonl`, `events.jsonl`, `flows.jsonl`, `detections.jsonl`.
- Biến thể, trong `variant_close_and_reset/`: bốn file cùng tên.
- Do `main.py` ghi (qua `run_case_ids`), sinh lại mỗi lần chạy, không sửa tay; trường `file` là đường dẫn tương đối so với gốc repo.

## Kết luận
**PASS.**

Chạy: `pytest TEST/BT3/T08_flow_established`.
