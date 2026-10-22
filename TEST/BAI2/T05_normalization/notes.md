# T05 — Normalization (case 01)

Case gồm hai nửa: (A) 4 packet trong `input.pcap`; (B) 3 event tổng hợp dựng trong `test_t05_normalization.py` (đưa thẳng vào Decoder → Preprocessor → Flow Tracker qua `run_events`), vì giá trị như protocol `tcp`/`Http`/`ip` hay IP có khoảng trắng không thể có trong gói tin thật.

## Input
**A. `input.pcap`** (tạo bằng `make_pcap.py`):
1. `GET /dir%2fsub/../x%2e?Q=%2f` với header `HOST: WwW.ExAmPlE.CoM`, `User-AGENT`, `ACCEPT-language`, và `X-Tag: a` + `x-tag: b` (trùng tên, khác chữ hoa/thường)
2. DNS query `WWW.Example.COM.`
3. DNS response: `WWW.Example.COM.` CNAME `Edge.CDN-Example.NET.` và `Edge.CDN-Example.NET.` A `192.0.2.7`
4. `GET /index.html` với header đã chữ thường (biến thể: không cần chuẩn hoá)

**B. Event tổng hợp:** (1) `network_protocol="ip"`, `transport_protocol="tcp"`, `app_protocol="Http"`, `src_ip=" 10.0.0.1 "`, `method="get"`, `uri="/A%2fb/../c?x=%2f"`, `host="WwW.ExAmPlE.CoM:8080"`, ba header chữ hoa; (2) event HTTP đã sạch; (3) DNS có CNAME, NS, TXT viết hoa/thường lẫn lộn.

## Kết quả mong đợi (tính tay)
| Giá trị gốc | Quy tắc | Sau chuẩn hoá |
|---|---|---|
| Tên header `HOST`, `User-AGENT`, `ACCEPT-language` | tên header luôn chữ thường | `host`, `user-agent`, `accept-language` |
| `Host: WwW.ExAmPlE.CoM` | hạ chữ thường (giữ nguyên cổng nếu có) | `www.example.com` (`www.example.com:8080` ở nửa B) |
| `X-Tag: a` + `x-tag: b` | header trùng tên gộp bằng `, ` | `x-tag: "a, b"` |
| Path `/dir%2fsub/../x%2e` | hex của percent viết hoa; **không** thu gọn `/../` | `/dir%2Fsub/../x%2E` (không chứa query) |
| Query DNS `WWW.Example.COM.` | hạ chữ thường, bỏ đúng một dấu chấm cuối | `www.example.com` |
| CNAME/NS: tên **và** dữ liệu là tên miền | hạ chữ thường, bỏ dấu chấm cuối | `edge.cdn-example.net`, `ns1.example.com` |
| Bản ghi A: dữ liệu là địa chỉ IP | không đụng | `192.0.2.7` |
| TXT: dữ liệu là văn bản tự do | không đụng (chỉ chuẩn hoá tên bản ghi) | `KeepTHIS.Case.` |
| `ip` / `tcp` / `Http` (nửa B) | alias → tên chuẩn | `IPv4` / `TCP` / `HTTP` |
| `" 10.0.0.1 "` (nửa B) | bỏ khoảng trắng, dạng chuẩn | `10.0.0.1` |

- **Dữ liệu gốc không đổi:** `app_fields.uri`, `header_pairs`, `queries`, `answers`, `host` giữ nguyên; bản chuẩn hoá nằm ở khóa riêng (`headers_normalized`, `path_normalized`, `host_normalized`, `queries_normalized`, `answers_normalized`).
- `processing_action`: packet cần chuẩn hoá → `normalized`; packet đã sạch (packet 4 của pcap, event 2 của nửa B) → `none`.
- `preprocess_status="valid"` cho mọi event; protocol cấp event luôn `IPv4`/`TCP`|`UDP`/`HTTP`|`DNS`.
- `host_normalized` chỉ xuất hiện ở nửa B: parser HTTP của Bài 1 không đưa khóa `host` vào `app_fields` (Host nằm trong `header_pairs`).

## Kết quả thực tế
`pytest .../T05_normalization`: 12 passed (7 test nửa pcap, 5 test nửa tổng hợp). Đối chiếu `events.jsonl` (4 event, đều `status="OK"`, `preprocess_status="valid"`, `reason=[]`):

| Packet | Dữ liệu gốc (giữ nguyên) | Bản chuẩn hoá | `processing_action` |
|---|---|---|---|
| 1 (HTTP) | `header_pairs` = `HOST`, `User-AGENT`, `ACCEPT-language`, `X-Tag`, `x-tag`; `uri` = `/dir%2fsub/../x%2e?Q=%2f` | `headers_normalized` = `{host: www.example.com, user-agent: Test/1.0, accept-language: en, x-tag: "a, b"}`; `path_normalized` = `/dir%2Fsub/../x%2E` | `normalized` |
| 2 (DNS query) | `queries[0].name` = `WWW.Example.COM` | `queries_normalized[0].name` = `www.example.com` | `normalized` |
| 3 (DNS response) | `answers`: CNAME `WWW.Example.COM` → `Edge.CDN-Example.NET`; A `Edge.CDN-Example.NET` → `192.0.2.7` | `answers_normalized`: CNAME `www.example.com` → `edge.cdn-example.net`; A `edge.cdn-example.net` → `192.0.2.7` (data địa chỉ IP không đổi) | `normalized` |
| 4 (HTTP sạch) | header chữ thường, `/index.html` | `headers_normalized` = `{host: example.com, user-agent: test}`, `path_normalized` = `/index.html` | `none` |

- `decoded_fields.uri` của packet 1 là `/dir/sub/../x.?Q=/` (Decoder giải mã percent trên bản sao); `/../` vẫn còn, dấu hiệu path traversal không bị mất.
- DNS: `decode_status="SKIPPED"`, `decoded_fields={}`; query và response cùng `flow_id` `ef2a9239582f1191` (`direction` forward/backward, `flow_state="ACTIVE"`).
- Ghi chú: khóa trong query DNS là `qtype`, trong answer là `type`. `dns_parser` đã bỏ dấu chấm cuối khi parse, nên bước "bỏ một dấu chấm cuối" được kiểm tra bằng event tổng hợp (nửa B: `WWW.Example.COM.` → `www.example.com`).
- Nửa B (event tổng hợp): `ip`/`tcp`/`Http` → `IPv4`/`TCP`/`HTTP`; `" 10.0.0.1 "` → `10.0.0.1`; `host_normalized` = `www.example.com:8080`; `path_normalized` = `/A%2Fb/../c`; CNAME/NS lowercase, TXT `KeepTHIS.Case.` giữ nguyên; event đã sạch → `none`; mọi khóa gốc trong `app_fields` không đổi.
- Độ dài khớp tính tay: `raw_length` = 14 + 20 + `payload_length` (181 = 54 + 127, 75, 160, 119).
- Không có key `payload` trong log; không crash.

## Kết luận
PASS