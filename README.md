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

**Bài 2** (đang thực hiện) bổ sung 3 module **Decoder**, **Preprocessor** và **Flow/Connection Tracker** lên trên pipeline của Bài 1 - xem mục "Trạng thái hiện tại".

## Trạng thái hiện tại

### Bài 1 — Packet Capture & Parser

Hoàn thành: pipeline chạy end-to-end (`main.py` -> capture live/pcap -> network -> transport -> detector -> application -> chuẩn hóa `IDSEvent` -> ghi ra `output/events.jsonl`) và vượt qua toàn bộ 12 test case bắt buộc của đề bài (xem thư mục `TEST/part1-packet-capture-test/`).

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
| #18 | Scaffold, gom test Bài 1 vào `TEST/part1-packet-capture-test/`, config loader, PCAP builder | Hoàn thành |
| #19 | Mở rộng `IDSEvent`, schema `Flow`, bổ sung HTTP/SMTP parser cho Decoder | Hoàn thành |
| #20 | Decoder | Hoàn thành |
| #22 | Preprocessor | Hoàn thành |
| #23 | Flow Tracker: key, direction, flow table, thống kê cơ bản | Hoàn thành |
| #24 | Theo dõi kết nối TCP | Hoàn thành |
| #25 | UDP flow, idle timeout, giải phóng flow hết hạn | Đang triển khai |
| #26 | Tích hợp pipeline, `flows.jsonl`, CLI | (Chưa bắt đầu) |
| #27 | Chạy test T01-T14 + Regression test Bài 1 | (Chưa bắt đầu) |

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

> Lưu ý: live capture cần quyền root (hoặc cấp quyền `cap_net_raw` cho Python) để có thể mở interface ở chế độ bắt gói tin trực tiếp. Nhấn `Ctrl+C` để dừng chế độ `--interface`.

### Kết quả output

Mỗi packet sau khi qua pipeline được ghi thành 1 dòng JSON vào **`output/events.jsonl`** (đường dẫn mặc định, tạo tự động nếu chưa tồn tại; tính tương đối theo thư mục chạy lệnh — luôn chạy `main.py` từ thư mục gốc repo). Ngoài ra chương trình cũng in log tóm tắt ra console theo thời gian thực (packet OK định kỳ mỗi 100 gói, packet `MALFORMED`/`UNKNOWN`/`IGNORED` được log riêng).

Cấu hình `config/settings.yaml` gồm:
- `ports`: mapping port  -> tên application protocol dùng cho detector port-based.
- `unknown_policy` (`log` hoặc `skip`): quyết định hành vi khi không nhận diện được application protocol nào — `log` vẫn ghi event ra JSONL với `app_protocol="UNKNOWN"`; `skip` đặt `status="IGNORED"` và không ghi ra file (chỉ áp dụng cho tầng Application, không ảnh hưởng packet non-IPv4 ở tầng Network).

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
- `close_reason` là `None` khi flow còn hoạt động; khi flow được xuất ra có thể là `tcp_closed`, `tcp_reset`, `idle_timeout`, `handshake_timeout`, `port_reuse`, `evicted` hoặc `flush`.

## Cấu trúc thư mục

```
.
├── README.md
├── requirements.txt
├── .gitignore
├── main.py  # CLI entrypoint: --interface / --pcap
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
│   │   └── pipeline.py         # process_packet() — orchestrate network  -> transport  -> detector  -> application  -> IDSEvent
│   ├── decoder/               # [Part 2] Giải mã URL/form, HTML entity, MIME Base64/QP, charset (đang phát triển)
│   ├── preprocessor/          # [Part 2] Validation, normalization, xử lý field thiếu (đang phát triển)
│   ├── flow/                  # [Part 2] Flow/Connection Tracker: 5-tuple, TCP state, UDP, timeout (đang phát triển)
│   └── utils/
│       ├── safe.py            # Decorator @safe_parse — bắt lỗi chung cho mọi parser, trả status="MALFORMED"
│       └── config.py          # Load, merge mặc định và validate config/settings.yaml
├── config/
│   └── settings.yaml   # Mapping port cho từng application protocol, policy xử lý protocol không xác định
└── TEST/
    ├── part1-packet-capture-test/ # 12 test case bắt buộc của Bài 1, mỗi case một thư mục riêng
    ├── part2-decoder-to-flowtracker-test/
    │   └── unit/              # unit test theo từng module
    └── helpers/
        └── pcap_builder.py    # Dựng PCAP có timestamp và MAC cố định phục vụ test
```

Cấu trúc này được thiết kế để mở rộng cho các bài tập tiếp theo trong cùng repo: mỗi module IDS mới (feature extraction, phát hiện port scan, cảnh báo...) sẽ được thêm vào như một thành phần song song trong `src/`, dùng chung schema `IDSEvent` mà module này tạo ra.

## AI usage disclosure

Trong quá trình phát triển, Claude Sonnet 5.5 (Anthropic) được sử dụng như sau:

- **Bài 1 - Packet Capture**: vai trò **review code và đưa ra gợi ý chỉnh sửa** cho từng commit trước khi đưa lên repo - không viết thay toàn bộ code. Phần lớn code nộp bài do người thực hiện tự viết; Claude chỉ đọc lại, chỉ ra lỗi/rủi ro tiềm ẩn (ví dụ: sai lệch so với schema đã chốt, race condition, dữ liệu bị parse sai âm thầm) và đề xuất hướng sửa, việc quyết định áp dụng sửa nào do người thực hiện tự cân nhắc.
- **Bài 2 - Decoder, Preprocessor và Flow Tracker**: lập kế hoạch Issue/commit (timeline) cho Bài 2; review từng commit như ở Bài 1; với một số file, Claude đề xuất đoạn mã sửa kèm unit test để người thực hiện đối chiếu, tự kiểm tra và quyết định áp dụng.

Khi mở Pull Request, GitHub Copilot đóng vai trò reviewer tự động - các comment của Copilot mang tính tham khảo, không tự động áp dụng thay đổi vào code.