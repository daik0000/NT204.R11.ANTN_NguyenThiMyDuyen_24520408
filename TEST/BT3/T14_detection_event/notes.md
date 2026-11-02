# T14 – Detection Event

## Mục tiêu
Một Detection Event có đủ và đúng các field: định danh rule (`sid`, `rev`, `msg`, `priority`, `classtype`), gói (`timestamp`, `packet_id`, 5-tuple, `protocol`), ngữ cảnh (`application_protocol`, `flow_id`, `flow_direction`) và `matched`. `packet_id` và `flow_id` cho phép tra ngược về `events.jsonl` và `flows.jsonl`; case này đối chiếu chéo cả ba file.

## Input
- `rules.rules`: một rule (dòng 2):
  `alert tcp any any -> any 80 (msg:"Directory traversal detected"; flow:to_server,established; content:"../"; classtype:web-application-attack; priority:1; sid:100001; rev:1;)`
- `input.pcap` (do `make_pcap.py` dựng, md5 cố định `fbc36cd3f25ab61d0322a9bf4ff01361`), từ `10.0.0.5:52133` tới `192.168.1.20:80`: p1 SYN, p2 SYN/ACK, p3 ACK (flow thành `ESTABLISHED`), p4 `GET /../../etc/passwd HTTP/1.1`. Chạy bằng `main.py --pcap … --rules …`.
- Biến thể (chạy riêng, thư mục `variant_defaults_and_udp/`): `variants.rules` (sid 14101–14103) và `variants.pcap` gồm bốn gói trên cộng p5 (DNS query `10.0.0.5:5353 -> 192.168.1.20:53`) và p6 (DNS response chiều ngược lại).
- Cách nạp: bài test chạy `main.py` với `--rules`; cấu hình tạm có `engine.rule_files: []` nên không có rule mẫu nào khác bị nạp.

## Kết quả mong đợi (tính tay trước khi chạy)
Chỉ p4 có thể bắn (ba gói đầu không có payload) ⇒ `detections.jsonl` có **đúng một dòng**:

| Field | Giá trị | Cách tính |
|---|---|---|
| `sid` | 100001 | từ rule |
| `rev` | 1 | từ rule |
| `msg` | `Directory traversal detected` | từ rule |
| `priority` | 1 | từ rule |
| `classtype` | `web-application-attack` | từ rule |
| `timestamp` | `1700000000.3` | timestamp của gói 4 trong pcap (T + 0.3), đọc lại bằng Scapy |
| `packet_id` | 4 | gói thứ tư |
| `src_ip`, `src_port` | `10.0.0.5`, 52133 | |
| `dst_ip`, `dst_port` | `192.168.1.20`, 80 | |
| `protocol` | `TCP` | |
| `application_protocol` | `HTTP` | |
| `flow_id` | bằng `flow_id` của `packet_id` 4 trong `events.jsonl`, và có mặt trong `flows.jsonl` | đối chiếu chéo |
| `flow_direction` | `to_server` | người gửi là client của flow |
| `matched` | `[{"keyword": "content", "value": "../", "offset": 5, "length": 3}]` | `GET /` chiếm 5 byte, `../` bắt đầu ở 5 |

- Thứ tự field trong dòng JSON: `sid, rev, msg, priority, classtype, timestamp, packet_id, src_ip, src_port, dst_ip, dst_port, protocol, application_protocol, flow_id, flow_direction, matched`.
- Đối chiếu chéo: `events.jsonl` có 4 event cùng một `flow_id`; `flows.jsonl` có đúng 1 flow với `endpoint_a = 10.0.0.5:52133`, `endpoint_b = 192.168.1.20:80`, `packet_count = 4`, `state = ESTABLISHED`, `close_reason = flush`; event p4 có `flow_state = ESTABLISHED` và `direction = forward` (cùng khớp với Detection: `src_ip`, `src_port`, `dst_ip`, `dst_port`, `timestamp`, `application_protocol`).

Biến thể (`variants.rules`):

| sid | Rule | Gói | `rev` | `priority` | `classtype` | `protocol` / `application_protocol` | `flow_direction` | `matched` |
|---|---|---|---|---|---|---|---|---|
| 14101 | `tcp -> 80; content:"../"` (không `classtype`, `priority`, `rev`) | 4 | 1 (mặc định) | 3 (`engine.default_priority`) | `null` | TCP / HTTP | `to_server` | `../` 5/3 |
| 14102 | `udp -> 53` | 5 | 1 | 3 | `null` | UDP / DNS | `to_server` | `header` |
| 14103 | `udp <> 53; classtype:misc-activity; priority:2; rev:3` | 5 | 3 | 2 | `misc-activity` | UDP / DNS | `to_server` | `header` |
| 14103 | (cùng rule, chiều trả lời) | 6 | 3 | 2 | `misc-activity` | UDP / DNS | `to_client` | `header` |

⇒ 4 Detection: (4, 14101), (5, 14102), (5, 14103), (6, 14103). Mỗi `flow_id` có trong `events.jsonl` đúng gói đó và trong `flows.jsonl`; p5 và p6 cùng một flow UDP (khác flow TCP), nên có 2 flow. 14101 vẫn có `flow_direction = to_server` dù rule không có option `flow`: đó là vai trò của bên gửi, được báo cho mọi Detection có flow.

## Kết quả thực tế
Chạy `pytest TEST/BT3/T14_detection_event`: **32 test pass**, mọi giá trị khớp bảng tính tay (không phải sửa kỳ vọng).

- `detections.jsonl` đúng một dòng với đủ 16 field như bảng, đúng kiểu (`timestamp` là số thực, `flow_id` là chuỗi, `matched` là danh sách không rỗng) và đúng thứ tự; `timestamp = 1700000000.3` bằng timestamp của gói 4 đọc lại bằng Scapy; `flow_id = e1cf256a2e323739`.
- Đối chiếu chéo: `flow_id` của Detection bằng `flow_id` của event gói 4 và có trong `flows.jsonl` (flow 4 gói, `ESTABLISHED`, `flush`); `endpoint_a`, `endpoint_b`, 5-tuple, `timestamp`, `application_protocol` của Detection khớp event và flow.
- `rules_report.jsonl`: 1 dòng `valid` (dòng 2, sid 100001).
- Biến thể: `variant_defaults_and_udp/detections.jsonl` có 4 dòng đúng như bảng; hai Detection của 14103 cùng `flow_id` và khác flow TCP; `rev`, `priority`, `classtype` mặc định đúng.
- `main.py` exit 0; hai pcap dựng lại cho cùng md5; output hai lần chạy liên tiếp giống hệt từng byte.

## Bằng chứng trong thư mục
- Chạy chính, cạnh `input.pcap`: `rules_report.jsonl`, `events.jsonl`, `flows.jsonl`, `detections.jsonl`.
- Biến thể, trong `variant_defaults_and_udp/`: bốn file cùng tên.
- Do `main.py` ghi (qua `run_case_ids`), sinh lại mỗi lần chạy, không sửa tay; trường `file` là đường dẫn tương đối so với gốc repo.

## Kết luận
**PASS.**

Chạy: `pytest TEST/BT3/T14_detection_event`.
