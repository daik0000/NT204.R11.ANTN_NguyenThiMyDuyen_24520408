# NT204.R11.ANTN_NguyenThiMyDuyen_24520408
## Mục tiêu

Đây là repo bài tập lớn cho môn học **Hệ thống tìm kiếm, phát hiện và ngăn chặn xâm nhập**. Toàn bộ các bài tập trong môn học sẽ được phát triển tiếp trên cùng repo này, theo hướng xây dựng dần một hệ thống **Intrusion Detection System (IDS)** hoàn chỉnh bằng Python.

Bài tập đầu tiên (module này) xây dựng tầng **Packet Capture & Parser** - nền tảng cho toàn bộ các module IDS phía sau (feature extraction, port-scan detection, alerting...). Module có nhiệm vụ:

- Thu thập lưu lượng mạng từ **live traffic** (bắt trực tiếp trên network interface) hoặc từ **file PCAP** có sẵn, thông qua cùng một pipeline xử lý duy nhất.
- Phân tích các gói tin theo các giao thức được hỗ trợ:
  - Network: IPv4
  - Transport: TCP, UDP
  - Application: HTTP/1.x, DNS, SMTP
- Chuyển mỗi gói tin thành một **cấu trúc dữ liệu chuẩn hóa** (normalized IDS event), để các module IDS phía sau xử lý mà không cần truy cập trực tiếp vào raw packet hay object của thư viện capture.
- Đảm bảo không crash khi gặp packet lỗi, thiếu header, payload rỗng, hoặc protocol không được hỗ trợ.
- Ghi lại toàn bộ kết quả parse ra file theo định dạng JSON Lines, để tái sử dụng ở các bài tập tiếp theo.

**Bài 2** bổ sung 3 module **Decoder**, **Preprocessor** và **Flow/Connection Tracker** lên trên pipeline của Bài 1 - xem mục "Trạng thái hiện tại".

## Trạng thái hiện tại

### Bài 1 — Packet Capture & Parser

Hoàn thành: pipeline chạy end-to-end (`main.py` -> capture live/pcap -> network -> transport -> detector -> application -> chuẩn hóa `IDSEvent` -> ghi ra `output/events.jsonl`) và vượt qua toàn bộ 12 test case bắt buộc của đề bài (xem thư mục `TEST/BAI1/`).

### Bài 2 — Decoder, Preprocessor & Flow/Connection Tracker

**Mục tiêu**

Mở rộng pipeline của Bài 1 bằng 3 module, đầu vào là `IDSEvent` đã chuẩn hóa:

```
Capture -> Parser -> Decoder -> Preprocessor -> Flow Tracker -> (Feature Extractor — bài sau)
```

| Module | Nhiệm vụ chính |
|---|---|
| **Decoder** | Giải mã percent-encoding và `application/x-www-form-urlencoded` trong HTTP, HTML entity, MIME Base64/Quoted-Printable trong SMTP, ASCII/UTF-8; giữ nguyên dữ liệu gốc, byte lỗi chỉ đánh dấu `PARTIAL`, không crash |
| **Preprocessor** | Validation (`valid`/`partial`/`invalid`), chuẩn hóa (protocol, IP, domain, header, URI, timestamp), xử lý field thiếu và protocol không hỗ trợ, gắn metadata `preprocess_status`/`processing_action`/`reason` |
| **Flow Tracker** | Gom packet hai chiều theo 5-tuple, `flow_id` ổn định, xác định `direction`, máy trạng thái TCP (`HANDSHAKE -> ESTABLISHED -> CLOSING -> CLOSED/RESET`), UDP flow, idle timeout, thống kê trên mỗi flow, xuất `flows.jsonl` |

Yêu cầu chung: timeout, giới hạn kích thước và chính sách bỏ qua packet đều cấu hình được qua `config/settings.yaml`; một packet lỗi không được làm dừng chương trình.

**Decoder — hành vi chính** (`src/decoder/`)

- Chạy trên `event.payload` (bytes gốc, chỉ ở bộ nhớ) và **không bao giờ sửa `app_fields`**; kết quả nằm ở `decoded_fields`: `uri`, `body`, `form_params` (HTTP), `body` (SMTP DATA).
- Giải mã ở mức byte (percent-decode rồi mới giải mã ký tự), nên byte không hợp lệ được **đếm chính xác** (`invalid_byte_count`, `first_invalid_offset`) và event chỉ bị `PARTIAL`, không crash.
- HTML entity chỉ áp dụng cho body/giá trị form có content-type trong `decoder.html_entity_content_types`, **không bao giờ áp dụng cho URI**.
- Body nhị phân (`image/*`, `application/octet-stream`, `zip`…) -> `SKIPPED`; vượt `decoder.max_payload_bytes` -> cắt, `PARTIAL` và thêm `truncated_by_limit` vào `reason`.
- `decode_status` của event là trạng thái xấu nhất của các field (`FAILED > PARTIAL > OK > SKIPPED`); event `MALFORMED` hoặc `decoder.enabled=false` giữ `decode_status=None`.

**Preprocessor — hành vi chính** (`src/preprocessor/`)

| Mức | Ý nghĩa |
|---|---|
| `valid` | Đủ field bắt buộc, giá trị hợp lệ |
| `partial` | Dùng được nhưng suy giảm: protocol không hỗ trợ (ARP/IPv6/ICMP), thiếu transport, port 0, `decode_status` là `PARTIAL`/`FAILED` |
| `invalid` | Thiếu hoặc sai field bắt buộc (port ngoài miền, IP sai định dạng, timestamp `NaN`/tương lai quá ngưỡng, cờ TCP lạ, event `MALFORMED`) |

- Luồng: **validate -> normalize (bỏ qua nếu `invalid`) -> điền mặc định -> áp policy.** Chuẩn hoá không bao giờ che giấu dữ liệu rác.
- Chuẩn hoá protocol, IP, timestamp được làm **tại chỗ** trên field cấp event; dữ liệu trong `app_fields` giữ nguyên và bản chuẩn hoá nằm ở key riêng: `headers_normalized`, `path_normalized`, `host_normalized`, `queries_normalized`, `answers_normalized`. `/../` và `//` trong path được giữ nguyên để IDS còn thấy dấu hiệu path traversal.
- `processing_action`: `invalid` -> `flagged` (hoặc `dropped` nếu `invalid_policy: drop`); protocol không hỗ trợ -> `flagged` (hoặc `skipped` nếu `unsupported_policy: skip`); còn lại `normalized` nếu có giá trị được chuẩn hoá, `defaults_filled` nếu chỉ bổ sung mặc định, ngược lại `none`. Event `skipped`/`dropped` không vào Flow Tracker và không được ghi log.
- Nếu chính stage Preprocessor gặp lỗi bất ngờ, event ra với `preprocess_status="invalid"`, `processing_action="flagged"` và `error_info.layer="preprocessor"`.
- Ba policy độc lập: `unknown_policy` (Bài 1, tầng Application), `unsupported_policy` (`mark`/`skip`), `invalid_policy` (`flag`/`drop`).

**Test bắt buộc:** 14 test case T01-T14 (HTTP URL decode, HTML entity, SMTP Base64/QP, invalid bytes, normalization, missing field, TCP handshake, bidirectional flow, TCP close, UDP query/response, concurrent flows, idle timeout, statistics, malformed event).

**Tiến độ hiện tại**

| Issue | Nội dung | Trạng thái |
|---|---|---|
| #18 | Scaffold, gom test Bài 1 vào `TEST/BAI1/`, config loader, PCAP builder | Hoàn thành |
| #19 | Mở rộng `IDSEvent`, schema `Flow`, bổ sung HTTP/SMTP parser cho Decoder | Hoàn thành |
| #20 | Decoder | Hoàn thành |
| #22 | Preprocessor | Hoàn thành |
| #23 | Flow Tracker: key, direction, flow table, thống kê cơ bản | Hoàn thành |
| #24 | Theo dõi kết nối TCP | Hoàn thành |
| #25 | UDP flow, idle timeout, giải phóng flow hết hạn | Hoàn thành |
| #26 | Tích hợp pipeline, `flows.jsonl`, CLI | Hoàn thành |
| #27 | Chạy test T01-T14 + Regression test Bài 1 | Hoàn thành |

### Vòng đời flow: timeout, hết hạn, giải phóng

Mọi mốc thời gian dùng **event-time** (timestamp của packet, không phải đồng hồ máy): `clock` là mốc lớn nhất đã thấy từ các event theo dõi được (event `invalid` hoặc timestamp không hữu hạn không làm `clock` tiến). Tất cả khoá nằm trong section `flow` của `config/settings.yaml`; thiếu hoặc sai giá trị thì dùng mặc định bên dưới (trùng với file cấu hình), không làm dừng chương trình.

| Loại flow / trạng thái | Khoá cấu hình | Mặc định (giây) | `close_reason` khi hết hạn |
|---|---|---|---|
| UDP | `udp_idle_timeout_sec` | 60 | `idle_timeout` |
| TCP `HANDSHAKE` | `tcp_handshake_timeout_sec` | 30 | `handshake_timeout` |
| TCP `CLOSED` / `RESET` (giữ để hứng ACK/retransmit muộn) | `tcp_closed_linger_sec` | 10 | `tcp_closed` / `tcp_reset` |
| TCP `ESTABLISHED` / `CLOSING` | `tcp_idle_timeout_sec` | 300 | `idle_timeout` |

- **Biên hết hạn:** flow hết hạn khi `now - last_seen > timeout` (lớn hơn **hẳn**; đúng bằng timeout thì chưa hết hạn). `duration` của flow hết hạn là `last_seen - start_time`, không cộng thời gian chờ.
- **Hết hạn lazy:** khi một packet đến, nếu flow cùng 5-tuple đã quá hạn thì flow cũ được xuất trước rồi packet mở flow mới (hai phiên không bị trộn dù chưa đến lượt quét).
- **Quét định kỳ (`sweep`):** chạy khi `clock` tiến thêm ít nhất `sweep_interval_sec` (mặc định 1.0) kể từ lần quét trước; duyệt toàn bảng O(n), gom danh sách hết hạn trước rồi mới xuất.
- **Tái dùng cổng:** SYN thuần (không ACK) tới flow đang `CLOSED`/`RESET` còn trong thời gian giữ -> flow cũ xuất với `port_reuse`, flow mới bắt đầu. Quá thời gian giữ thì flow cũ xuất `tcp_closed`/`tcp_reset`.
- **Giới hạn bộ nhớ:** bảng đầy (`max_active_flows`, mặc định 100000) thì flow lâu chưa hoạt động nhất bị xuất với `evicted` trước khi thêm flow mới.
- **Flush khi thoát:** `flush()` xuất mọi flow còn lại, từ cũ đến mới: `CLOSED`/`RESET` giữ `tcp_closed`/`tcp_reset`, còn lại là `flush`. Flow hết hạn nhưng chưa kịp quét lúc kết thúc cũng nhận `flush`.

### Trạng thái TCP

Hàm thuần `next_state()` (`src/flow/tcp_state.py`) tính trạng thái kế tiếp theo độ ưu tiên **RST > SYN > FIN > ACK**. `CLOSED`/`RESET` là trạng thái cuối: packet đến muộn không đổi trạng thái.

| Từ trạng thái | Sự kiện | Sang trạng thái |
|---|---|---|
| (packet đầu) | SYN | `HANDSHAKE` |
| (packet đầu) | SYN/ACK (bắt giữa chừng) | `HANDSHAKE`, `midstream=true` |
| (packet đầu) | ACK / FIN / cờ khác, không SYN (bắt giữa chừng) | `ESTABLISHED` (FIN thì `CLOSING`), `midstream=true` |
| `HANDSHAKE` | SYN/ACK từ chiều `backward` | `HANDSHAKE` (ghi nhận đã thấy SYN/ACK) |
| `HANDSHAKE` | ACK từ bên không gửi SYN/ACK | `ESTABLISHED` |
| `ESTABLISHED` | FIN một chiều | `CLOSING` |
| `CLOSING` | FIN chiều còn lại | `CLOSED` (hoặc chờ ACK cuối nếu `tcp_close_requires_final_ack: true`) |
| `CLOSING` | ACK cuối khi đã đủ hai FIN và `tcp_close_requires_final_ack: true` | `CLOSED` |
| bất kỳ (chưa kết thúc) | RST | `RESET` |

SYN thuần tới flow đang `CLOSED`/`RESET` còn trong thời gian giữ là tái dùng cổng (xem "Vòng đời flow"), không đổi trạng thái flow cũ.

### Giới hạn đã biết

- Event-time chỉ tiến khi có packet mới: ở chế độ `--interface`, nếu traffic ngừng hẳn thì flow chưa hết hạn cho tới packet kế tiếp hoặc lúc thoát (`flush`). Hướng mở rộng: `capture_live` phát tín hiệu heartbeat khi hàng đợi rỗng.
- `sweep` duyệt toàn bảng O(n) mỗi `sweep_interval_sec`; timeout khác nhau theo loại flow nên LRU thuần không đủ để dừng sớm. Hướng cải tiến: hàng đợi ưu tiên theo thời điểm hết hạn.
- Packet đến muộn hơn `clock` (không đúng thứ tự) không làm flow hết hạn và không kéo `clock` lùi; flow đã bị xuất rồi không được "mở lại".
- `flows.jsonl` chỉ có dòng cho flow **đã xuất**. Nếu chương trình bị kill cưỡng bức (`SIGKILL`, mất điện) thì các flow còn trong bảng không được ghi; thoát bằng `Ctrl+C`, hết pcap hoặc lỗi bắt được thì luôn `flush`.
- Parse từng packet độc lập: không ghép lại TCP, không giải nén gzip/chunked, không giải mã TLS.
- Nhánh dự phòng khi xuất flow (key trong bảng không khớp key dựng lại) chỉ xoá entry chứ không gọi callback; tình huống này không xảy ra khi bảng chỉ được ghi qua `update()`. Hướng cải tiến: truyền key của bảng vào `_export_flow`.

### Bài 3 — Core Engine & Snort Rule Matching

**Trạng thái:** đang thực hiện (skeleton + cấu hình đã có, engine chưa cài đặt).

**Mục tiêu**

Xây dựng Core Engine đối sánh `IDSEvent` / `Flow` với bộ rule kiểu Snort nạp từ file, rồi sinh cảnh báo. Signature nằm hoàn toàn trong file `.rules`, **không hard-code trong source code Python**.

```
Capture -> Parser -> Decoder -> Preprocessor -> Flow Tracker -> Rule Engine -> detections.jsonl / rules_report.jsonl
```

- `engine.enabled: false` trong `config/settings.yaml` đưa pipeline về đúng hành vi Bài 2 (phục vụ hồi quy).
- Rule nạp theo thứ tự `engine.rule_files`; file lỗi hoặc không tồn tại chỉ cảnh báo, các file khác vẫn được nạp. Rule có thể tắt theo file (`enabled`) hoặc theo `engine.disabled_sids`.

**Cấu hình** (section `engine` trong `config/settings.yaml`, kiểm tra ngay khi load, sai thì `ValueError`):

| Khoá | Mặc định | Ý nghĩa |
|---|---|---|
| `enabled` | `true` | Bật/tắt engine |
| `rule_files` | `[{path: config/rules/local.rules, enabled: true}]` | Danh sách file rule, đọc theo thứ tự |
| `disabled_sids` | `[]` | Danh sách sid bị tắt |
| `default_priority` | `3` | Priority dùng khi rule không khai báo (số nguyên >= 1) |

**Cấu trúc**

```
src/rules/        # Parser/model của rule (đọc file .rules)
src/engine/       # Core Engine: đối sánh rule và sinh detection
config/rules/
└── local.rules   # Rule mẫu chạy thử (bộ rule chấm nằm trong từng test case)
TEST/BT3/         # Test case Bài 3: *.rules, input.pcap, events.jsonl, flows.jsonl, detections.jsonl, rules_report.jsonl
└── unit/         # Unit test theo module (test_engine_config.py, ...)
```

**Cách chạy test**

```bash
pytest TEST/BT3
```

Tên file test phải duy nhất trong toàn repo (thư mục test không có `__init__.py`).

**Quyết định thiết kế**

- `output/rules_report.jsonl` được **ghi đè** mỗi lần chạy vì mô tả lần nạp rule hiện tại, khác với `events.jsonl`, `flows.jsonl` và `detections.jsonl` ghi nối tiếp.
- Báo cáo ghi mọi dòng rule (`valid`, `invalid`, `unsupported`, `disabled`), rule hợp lệ có `reason: null`.
- Một dòng rule bị lỗi parser có thể sinh hai cảnh báo: chi tiết ngoại lệ (`Parser failed on ...`) và mã lý do (`rejected: invalid:internal_error`).
- Trong rule, `any` phải viết chữ thường (`ANY` bị từ chối là `bad_ip`/`bad_port`). IP chỉ nhận IPv4: địa chỉ đơn hoặc CIDR với prefix là số thập phân; không nhận netmask dạng chấm, số 0 đứng đầu, biến `$VAR`, phủ định `!` hay danh sách `[...]`.
- `flags` dùng chữ in hoa `FSRPAUCE` hoặc `0`; `!` đứng trước, `+` và `*` đứng sau chữ (`SA+`, `!SA`). Mặt nạ (`SA,12`) là `unsupported:flags_mask`. Vị trí của `+`/`*` theo tài liệu Snort chưa được đối chiếu (xem mục "Giới hạn đã biết").
- Thứ tự phân loại một dòng rule: cấu trúc, header, option được hỗ trợ, keyword ngoài phạm vi; `invalid` ở bất kỳ bước nào thắng mọi `unsupported`. Rule sai cấu trúc hoặc sai số token header không có `sid` trong báo cáo (`sid: null`); các lỗi khác mang `sid` nếu rule có đúng một `sid` hợp lệ. `content:!"..."` vẫn được parse đầy đủ để lỗi liên-option không bị che.

_(cập nhật dần)_

**Giới hạn đã biết**

- `flags:+SA` / `flags:*SA` (modifier `+`, `*` đứng trước chữ) hiện bị từ chối là `invalid:bad_option_value:flags`; cần đối chiếu tài liệu Snort của môn học rồi quyết định có nhận hay không.

_(cập nhật dần)_

## Cách chạy

Môi trường: Linux, Python 3.10+.

```bash
pip install -r requirements.txt
```

Live capture từ một network interface (cần quyền root):

```bash
sudo python main.py --interface eth0
```

Live capture với BPF filter tùy chỉnh ở tầng kernel (mặc định là `"tcp or udp"`):

```bash
sudo python main.py --interface eth0 --bpf-filter "tcp port 80"
```

Import và xử lý packet từ file PCAP (tham số `--bpf-filter` không áp dụng cho chế độ này):

```bash
python main.py --pcap test.pcap
```

Chạy với cấu hình và đường dẫn output tùy chọn (Bài 2):

```bash
python main.py --pcap test.pcap --config config/settings.yaml \
    --events-output output/events.jsonl --flows-output output/flows.jsonl
```

| Tham số | Mặc định | Ý nghĩa |
|---|---|---|
| `--pcap FILE` / `--interface IF` | (bắt buộc chọn một) | Nguồn packet: file PCAP hoặc interface live; hai tham số loại trừ nhau |
| `--config FILE` | `config/settings.yaml` | File cấu hình; giá trị sai (ví dụ timeout âm) làm chương trình dừng với exit code 1 |
| `--events-output FILE` | `output/events.jsonl` | Nơi ghi `IDSEvent` |
| `--output FILE` | (không) | Tên cũ của Bài 1, tương đương `--events-output`; nếu có cả hai thì `--events-output` được ưu tiên |
| `--flows-output FILE` | `output/flows.jsonl` | Nơi ghi flow record khi flow kết thúc |
| `--bpf-filter EXPR` | `"tcp or udp"` | BPF filter, chỉ áp dụng cho `--interface` |

Khi kết thúc (hết pcap, `Ctrl+C` hoặc lỗi giữa chừng), chương trình luôn **flush** để xuất mọi flow còn lại ra `flows.jsonl`, đóng file output rồi in một dòng tóm tắt. Exit code là 0 khi chạy xong hoặc bị `Ctrl+C`, 1 khi lỗi (file không tồn tại, thiếu quyền, cấu hình sai, lỗi bất ngờ).

> Lưu ý: live capture cần quyền root (hoặc cấp quyền `cap_net_raw` cho Python) để có thể mở interface ở chế độ bắt gói tin trực tiếp. Nhấn `Ctrl+C` để dừng chế độ `--interface`.

### Kết quả output

Chương trình ghi hai file JSON Lines (đường dẫn mặc định, tạo tự động nếu chưa tồn tại; tính tương đối theo thư mục chạy lệnh — luôn chạy `main.py` từ thư mục gốc repo):

- **`output/events.jsonl`**: mỗi packet sau khi qua pipeline là 1 dòng `IDSEvent`. Event bị bỏ qua có chủ ý (`unknown_policy: skip`, `unsupported_policy: skip`, `invalid_policy: drop`) không được ghi.
- **`output/flows.jsonl`**: mỗi flow là 1 dòng `Flow`, ghi **khi flow được xuất** (kết thúc, hết hạn, bị đẩy khỏi bảng hoặc `flush` lúc thoát). Thứ tự dòng là thứ tự xuất, không phải thứ tự bắt đầu flow.

Ngoài ra chương trình in log ra console theo thời gian thực (packet OK định kỳ mỗi 100 gói, packet `MALFORMED`/`UNKNOWN`/`IGNORED` được log riêng) và một dòng tóm tắt khi kết thúc:

```
System shutdown complete. Summary: packets=4, flows=3, active_before_flush=3, preprocess_status={valid=2, partial=1, invalid=1}
```

`flows` là số flow đã xuất, `active_before_flush` là số flow còn trong bảng ngay trước khi `flush`.

Cấu hình `config/settings.yaml` gồm:
- `ports`: mapping port  -> tên application protocol dùng cho detector port-based.
- `flow`: các khoá timeout và giới hạn của Flow Tracker (bảng dưới).
- `decoder` (`enabled`, `max_payload_bytes`, `html_entity_content_types`) và `preprocessor` (`unsupported_policy`: `mark`/`skip`, `invalid_policy`: `flag`/`drop`): xem phần Bài 2 ở trên.
- `unknown_policy` (`log` hoặc `skip`): quyết định hành vi khi không nhận diện được application protocol nào — `log` vẫn ghi event ra JSONL với `app_protocol="UNKNOWN"`; `skip` đặt `status="IGNORED"` và không ghi ra file (chỉ áp dụng cho tầng Application, không ảnh hưởng packet non-IPv4 ở tầng Network).

Các khoá của section `flow` (mặc định trong code trùng với `settings.yaml`; giá trị phải là số hữu hạn > 0, sai thì chương trình dừng khi khởi động):

| Khoá | Mặc định | Ý nghĩa |
|---|---|---|
| `udp_idle_timeout_sec` | 60 | Idle timeout của UDP flow |
| `tcp_handshake_timeout_sec` | 30 | Hết hạn của TCP flow chưa bắt tay xong |
| `tcp_closed_linger_sec` | 10 | Thời gian giữ flow `CLOSED`/`RESET` để hứng packet muộn và phát hiện tái dùng cổng |
| `tcp_idle_timeout_sec` | 300 | Idle timeout của TCP `ESTABLISHED`/`CLOSING` |
| `max_active_flows` | 100000 | Số flow tối đa trong bảng; đầy thì đẩy flow lâu chưa hoạt động nhất |
| `sweep_interval_sec` | 1.0 | Khoảng event-time giữa hai lần quét hết hạn |
| `tcp_close_requires_final_ack` | `false` | `true`: chỉ `CLOSED` sau khi thấy ACK cuối của hai FIN |

### Tối ưu buffer OS cho live capture

Khi capture traffic thật với tốc độ cao, buffer socket mặc định của Linux có thể không đủ lớn, dẫn đến mất gói tin (packet loss) ở tầng kernel trước khi packet kịp lên tới Python. Có thể tăng buffer bằng:

```bash
sudo sysctl -w net.core.rmem_max=26214400
sudo sysctl -w net.core.rmem_default=26214400
```

Hai giá trị trên chỉ có hiệu lực cho phiên làm việc hiện tại; để giữ lại sau khi khởi động lại máy, thêm 2 dòng tương ứng vào `/etc/sysctl.conf` rồi chạy `sudo sysctl -p`.

## IDSEvent

Mỗi gói tin sau khi qua pipeline sẽ được chuẩn hóa thành một dòng JSON theo schema `IDSEvent` (định nghĩa tại `src/models/event.py`), gồm các nhóm field sau:

- **Định danh & thời gian**: `packet_id`, `timestamp`
- **Network layer**: `src_ip`, `dst_ip`, `network_protocol`, `network_fields` (chi tiết riêng của IPv4 như `ttl`, `header_length`)
- **Transport layer**: `src_port`, `dst_port`, `transport_protocol`, `transport_fields` (với TCP: `flags`, `seq`, `ack`, `window`; với UDP: `length`)
- **Application layer**: `app_protocol` (`None` = detector chưa chạy; `"UNKNOWN"` = đã chạy nhưng không nhận diện được), `detection_method` (`port`/`payload`/`port+payload`), `app_fields` (chi tiết riêng theo từng giao thức HTTP/DNS/SMTP)
- **Metadata**: `raw_length` (độ dài cả frame), `payload_length` (độ dài phần payload của gói IP, tức đoạn tầng giao vận **gồm cả header TCP/UDP** - không phải độ dài dữ liệu ứng dụng), `status` (`OK`/`UNKNOWN`/`MALFORMED`/`IGNORED`), `error_info` (chi tiết lỗi khi `status="MALFORMED"`, gồm `layer` và `detail`; luôn `None` khi `status="IGNORED"` vì đây không phải lỗi, chỉ là packet bị bỏ qua có chủ ý theo `unknown_policy`)

Các nhóm field bổ sung ở Bài 2 (đều có giá trị mặc định, nên code Bài 1 không bị ảnh hưởng):

- **Decoder**: `decoded_fields` (dữ liệu đã giải mã theo từng nguồn; dữ liệu gốc trong `app_fields` luôn được giữ nguyên), `decode_status` (`OK`/`PARTIAL`/`FAILED`/`SKIPPED`; `None` = Decoder chưa chạy)
- **Preprocessor**: `timestamp_iso` (UTC ISO-8601), `preprocess_status` (`valid`/`partial`/`invalid`; `None` = chưa chạy), `processing_action` (`none`/`normalized`/`defaults_filled`/`flagged`/`skipped`/`dropped`), `reason` (danh sách mã lý do, `[]` khi không có; ví dụ `missing_src_ip`, `invalid_src_port`, `unsupported_transport:ICMP`, `malformed_parse_tcp`, `truncated_by_limit`)
- **Flow Tracker**: `flow_id`, `direction` (`forward`/`backward`), `flow_state` (trạng thái flow ngay sau khi xử lý packet này)
- **Chỉ trong bộ nhớ**: `payload` - bytes nguyên văn của tầng ứng dụng, dành cho Decoder (`b""` khi packet không có dữ liệu ứng dụng, `None` khi không tới được tầng transport). Field này **không bao giờ được ghi ra log** (`to_dict()` loại bỏ nó).

`status` (kết quả parse), `decode_status` (kết quả Decoder) và `preprocess_status` (kết quả validation) là ba trạng thái độc lập, không ghi đè nhau.

Một số `app_fields` được bổ sung để Decoder dùng trực tiếp:
- **HTTP**: `uri` (request-target nguyên văn, chưa giải mã), `header_pairs` (từng dòng header `[tên, giá trị]` giữ nguyên chữ hoa/thường, thứ tự và các dòng trùng), `body_offset` (vị trí bắt đầu body trong `payload`; `None` nếu chưa thấy dòng trống kết thúc header), `content_type`, `charset`, `content_length`.
- **SMTP DATA** (nội dung thư): `type="data"`, `mime_headers` (tên header viết thường), `body_offset`. Hai loại cũ vẫn là `type="command"` và `type="response"`.
- **Bản chuẩn hoá do Preprocessor thêm** (cạnh dữ liệu gốc, không ghi đè): `headers_normalized` (tên header viết thường, header trùng gộp bằng `, `, riêng `set-cookie` giữ dạng list), `path_normalized`, `host_normalized`, và với DNS `queries_normalized`, `answers_normalized`.

Đây là format dữ liệu duy nhất mà các module phía sau được phép sử dụng - không truy cập trực tiếp object của thư viện capture (Scapy). Kết quả được ghi liên tục ra file JSON Lines (mặc định `output/events.jsonl`) qua `src/logging/jsonl_logger.py`.

Mỗi parser (`src/parsers/`) được bọc bởi decorator `@safe_parse` (`src/utils/safe.py`) - bắt mọi lỗi phát sinh khi gặp packet dị dạng/thiếu header/payload quá ngắn, trả về `status="MALFORMED"` kèm `error_info` thay vì làm crash toàn bộ chương trình.

## Flow record

Schema `Flow` (định nghĩa tại `src/models/flow.py`) mô tả một kết nối/phiên hai chiều. Flow Tracker sẽ tạo và cập nhật các record này ở Issue #12-#14 và ghi ra `flows.jsonl` khi flow kết thúc.

| Nhóm | Field |
|---|---|
| Định danh | `flow_id`, `protocol` (`TCP`/`UDP`), `application_protocol`, `endpoint_a`, `endpoint_b` (mỗi endpoint là `{"ip", "port"}`) |
| Thời gian | `start_time`, `last_seen`, `duration` |
| Tổng thể | `packet_count`, `byte_count`, `payload_byte_count` |
| Hai chiều | `fwd_packet_count`, `fwd_byte_count`, `bwd_packet_count`, `bwd_byte_count` |
| TCP | `syn_count`, `ack_count`, `fin_count`, `rst_count`, `state` |
| Phụ trợ | `close_reason`, `midstream` |

Quy ước:
- `endpoint_a` là bên gửi packet đầu tiên được thấy (thường là bên khởi tạo); `forward` là chiều A -> B, `backward` là chiều B -> A.
- `duration` luôn được tính từ `last_seen - start_time` (không âm), không lưu riêng.
- `byte_count` là tổng độ dài frame (khớp cột *Bytes* của Wireshark -> Statistics -> Conversations); `payload_byte_count` chỉ tính dữ liệu tầng ứng dụng.
- Mỗi bộ đếm cờ là số packet **có mang cờ đó** (một packet SYN/ACK tăng cả `syn_count` lẫn `ack_count`). Đối chiếu tên với đề: `SYN_count` <-> `syn_count`, tương tự cho ACK/FIN/RST.
- `state` của TCP: `HANDSHAKE`, `ESTABLISHED`, `CLOSING`, `CLOSED`, `RESET`; với UDP luôn là `ACTIVE` (UDP không có trạng thái kết nối) và các bộ đếm cờ TCP bằng 0.
- `midstream` là `true` khi packet đầu tiên thấy được không phải SYN (capture bắt đầu giữa kết nối).
- `close_reason` là `None` khi flow còn hoạt động; khi flow được xuất ra có thể là `tcp_closed`, `tcp_reset`, `idle_timeout`, `handshake_timeout`, `port_reuse`, `evicted` hoặc `flush`.

Ví dụ một dòng của `flows.jsonl` (minh hoạ, giá trị tự chọn; một dòng thật nằm trên một dòng, ở đây xuống dòng cho dễ đọc):

```json
{"flow_id": "a1b2c3d4e5f6", "protocol": "UDP",
 "endpoint_a": {"ip": "10.0.0.1", "port": 5353}, "endpoint_b": {"ip": "10.0.0.2", "port": 53},
 "application_protocol": "DNS", "start_time": 1.0, "last_seen": 1.2, "duration": 0.2,
 "packet_count": 2, "byte_count": 180, "payload_byte_count": 96,
 "fwd_packet_count": 1, "fwd_byte_count": 80, "bwd_packet_count": 1, "bwd_byte_count": 100,
 "syn_count": 0, "ack_count": 0, "fin_count": 0, "rst_count": 0,
 "state": "ACTIVE", "close_reason": "flush", "midstream": false}
```

## Cấu trúc thư mục

```
.
├── README.md
├── requirements.txt
├── .gitignore
├── main.py  # CLI entrypoint: --interface / --pcap, --config, --events-output, --flows-output; flush khi thoát
├── src/
│   ├── models/
│   │   ├── event.py # Dataclass IDSEvent — schema chuẩn hóa dữ liệu sự kiện (gồm các field của Bài 2)
│   │   └── flow.py  # [Part 2] Dataclass Flow — schema flow record cho Flow Tracker
│   ├── logging/
│   │   └── jsonl_logger.py # JSONLLogger — ghi IDSEvent và Flow ra file JSON Lines
│   ├── capture/
│   │   ├── pcap_reader.py     # Đọc file PCAP theo generator, trả về (timestamp, raw_bytes)
│   │   └── live_capture.py    # Bắt live traffic qua producer-consumer queue, trả về (timestamp, raw_bytes)
│   ├── parsers/
│   │   ├── network/
│   │   │   └── ipv4_parser.py     # Decode raw bytes -> IPv4 fields (đây là nơi duy nhất tạo/hủy object Scapy)
│   │   ├── transport/
│   │   │   ├── tcp_parser.py      # Decode TCP segment: ports, flags, seq/ack, window
│   │   │   └── udp_parser.py
│   │   └── application/
│   │       ├── detector.py        # Nhận diện app protocol: port-based + payload signature, trả kèm detection_method
│   │       ├── http_parser.py     # Decode HTTP request/response: method, path, uri (nguyên văn), status_code, headers, header_pairs, body_offset, body preview
│   │       ├── dns_parser.py      # Decode DNS query/response qua scapy.layers.dns: queries, answers
│   │       └── smtp_parser.py     # Decode SMTP command/response theo dòng: multi-line, pipelining; DATA: mime_headers + body_offset
│   ├── pipeline/
│   │   └── pipeline.py         # Pipeline — orchestrate network -> transport -> detector -> application -> Decoder -> Preprocessor -> Flow Tracker; ghi events.jsonl và flows.jsonl; flush()/close()
│   ├── decoder/               # [Part 2] charset.py, url_decoder.py, html_decoder.py, mime_decoder.py, decoder.py (orchestrator)
│   ├── preprocessor/          # [Part 2] aliases.py, validator.py, normalizer.py, defaults.py, preprocessor.py (orchestrator)
│   ├── flow/                  # [Part 2] Flow/Connection Tracker: flow_key.py, flow_table.py, tcp_state.py, timeout.py, tracker.py
│   ├── rules/                 # [Part 3] Parser/model của rule Snort-style
│   ├── engine/                # [Part 3] Core Engine: đối sánh rule, sinh detection
│   └── utils/
│       ├── safe.py            # @safe_parse (parser, trả status="MALFORMED") và @safe_stage (Decoder/Preprocessor/Tracker, ghi error_info và trả lại event)
│       └── config.py          # Load, merge mặc định và validate config/settings.yaml
├── config/
│   ├── settings.yaml   # Mapping port, policy (unknown/unsupported/invalid), cấu hình decoder, preprocessor, flow và engine
│   └── rules/
│       └── local.rules # [Part 3] Rule mẫu chạy thử
└── TEST/
    ├── BAI1/ # 12 test case bắt buộc của Bài 1, mỗi case một thư mục riêng
    ├── BAI2/
    │   └── unit/              # unit test theo từng module
    ├── BT3/                   # [Part 3] test case Bài 3
    │   └── unit/              # unit test theo từng module
    └── helpers/
        └── pcap_builder.py    # Dựng PCAP có timestamp và MAC cố định phục vụ test
```

Cấu trúc này được thiết kế để mở rộng cho các bài tập tiếp theo trong cùng repo: mỗi module IDS mới (feature extraction, phát hiện port scan, cảnh báo...) sẽ được thêm vào như một thành phần song song trong `src/`, dùng chung schema `IDSEvent` mà module này tạo ra.

## AI usage disclosure

Trong quá trình phát triển, Claude Sonnet 5.5 (Anthropic) được sử dụng như sau:

- **Bài 1 - Packet Capture**: vai trò **review code và đưa ra gợi ý chỉnh sửa** cho từng commit trước khi đưa lên repo - không viết thay toàn bộ code. Phần lớn code nộp bài do người thực hiện tự viết; Claude chỉ đọc lại, chỉ ra lỗi/rủi ro tiềm ẩn (ví dụ: sai lệch so với schema đã chốt, race condition, dữ liệu bị parse sai âm thầm) và đề xuất hướng sửa, việc quyết định áp dụng sửa nào do người thực hiện tự cân nhắc.
- **Bài 2 - Decoder, Preprocessor và Flow Tracker**: lập kế hoạch Issue/commit (timeline) cho Bài 2; review từng commit như ở Bài 1; với một số file, Claude đề xuất đoạn mã sửa kèm unit test để người thực hiện đối chiếu, tự kiểm tra và quyết định áp dụng.
- **Bài 3 - Core Engine & Snort Rule Matching**: _(cập nhật dần)_

Khi mở Pull Request, GitHub Copilot đóng vai trò reviewer tự động - các comment của Copilot mang tính tham khảo, không tự động áp dụng thay đổi vào code.