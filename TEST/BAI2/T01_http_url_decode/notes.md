# T01 — HTTP URL decode (case 01)

## Input
`input.pcap` (tạo bằng `make_pcap.py`, 3 packet TCP → cổng 80, timestamp cố định):
1. `GET /search?q=%27%20OR%201%3D1&name=caf%C3%A9`
2. `POST /login`, `Content-Type: application/x-www-form-urlencoded`, body `user=a%40b.com&note=hello+world`
3. `GET /a+b/c%20d?x=1+2` (biến thể phụ)

## Kết quả mong đợi (tính tay)
| Giá trị | Giải mã | Kết quả |
|---|---|---|
| `%27` / `%20` / `%3D` | `'` / khoảng trắng / `=` | `q=' OR 1=1` |
| `%C3%A9` | byte `C3 A9` (UTF-8) | `é` → `name=café` |
| `%40` | `@` | `user=a@b.com` |
| `+` trong form body | khoảng trắng | `note=hello world` |
| `+` trong path (packet 3) | giữ nguyên | `/a+b/` |
| `+` trong query (packet 3) | khoảng trắng | `x=1 2` |
| `%20` trong path (packet 3) | khoảng trắng | `c d` |

- `app_fields.uri` giữ nguyên chuỗi percent-encoding gốc cho cả 3 packet.
- `decoded_fields.uri.value`: `/search?q=' OR 1=1&name=café`, `/login`, `/a+b/c d?x=1 2`.
- `decoded_fields.form_params.value` (packet 2): `[["user","a@b.com"],["note","hello world"]]`.
- `decode_status = "OK"` cho cả 3 event; không có `error_info`.

## Kết quả thực tế
`pytest .../T01_http_url_decode`: 11 passed. Đối chiếu `events.jsonl`:

| Packet | `app_fields.uri` (raw) | `decoded_fields.uri.value` | `encodings` | Khác |
|---|---|---|---|---|
| 1 | `/search?q=%27%20OR%201%3D1&name=caf%C3%A9` (nguyên vẹn) | `/search?q=' OR 1=1&name=café` | `["percent"]` | `decoded_fields.body` = `SKIPPED` (`empty_payload`) vì GET không có body |
| 2 | `/login` | `/login` | (không có, không có gì để giải mã) | `form_params.value` = `[["user","a@b.com"],["note","hello world"]]`, `encodings=["percent"]`, `body_offset=112`, `content_length=31` |
| 3 | `/a+b/c%20d?x=1+2` (nguyên vẹn) | `/a+b/c d?x=1 2` | `["percent"]` | `+` ở path giữ nguyên, `+` ở query thành khoảng trắng |

Chung cho cả 3 event:
- `status="OK"`, `app_protocol="HTTP"` (`detection_method="port+payload"`), `decode_status="OK"`, `error_info=null`.
- `preprocess_status="valid"`, `processing_action="normalized"` (do thêm `headers_normalized`, `path_normalized`), `reason=[]`.
- Không có key `payload` trong log.
- 3 `flow_id` khác nhau (`3442eca354e57074`, `1f493b1341b91ca7`, `5fea85b4c1bd6299`) vì 3 cổng nguồn khác nhau; `direction="forward"`, `flow_state="ESTABLISHED"` (packet đầu của mỗi flow là PSH/ACK nên được xem là bắt giữa chừng).
- Độ dài khớp tính tay: `raw_length` = 14 + 20 + 20 + payload HTTP (131 / 197 / 106); `payload_length` = 20 + payload HTTP (97 / 163 / 72).
- `timestamp_iso` khớp `timestamp` (`1700000000` → `2023-11-14T22:13:20+00:00`).

Ghi chú: `path_normalized` chỉ giữ phần đường dẫn (`/search`, `/a+b/c%20d`) và bỏ query; query vẫn còn nguyên trong `app_fields.uri` và `decoded_fields.uri`.

## Kết luận
PASS