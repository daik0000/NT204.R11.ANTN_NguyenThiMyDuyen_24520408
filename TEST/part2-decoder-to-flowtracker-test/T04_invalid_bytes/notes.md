# T04 — Invalid bytes (case 01)

## Input
`input.pcap` (tạo bằng `make_pcap.py`, 5 packet TCP → cổng 80, timestamp cố định). Các byte lỗi nằm trong `make_pcap.py` (dựng từ `bytes`) chứ không nằm trong log, vì payload thô không bao giờ được ghi ra `events.jsonl`.
1. `POST /upload`, `text/plain; charset=utf-8`, body = `61 62 63 FF FE 64 65 66` ("abc" + 2 byte lỗi + "def")
2. `GET /img?name=ab%FFcd`
3. `POST /upload`, body = `63 61 66 C3` ("caf" + nửa đầu của "é") — biến thể phụ
4. `POST /upload`, body = `61 00 62 FF 63` ("a", NUL, "b", `FF`, "c") — biến thể phụ
5. `POST /upload`, body `hello`

## Kết quả mong đợi (tính tay)
UTF-8 hợp lệ: byte `00–7F` đứng một mình; byte `C2–DF` phải đi kèm 1 byte nối `80–BF`. `FF`, `FE` không bao giờ hợp lệ; `C3` đứng cuối chuỗi là thiếu byte nối.

| Packet | Dữ liệu | Byte lỗi | `invalid_byte_count` | `first_invalid_offset` | Văn bản giải mã |
|---|---|---|---|---|---|
| 1 | `abc` `FF FE` `def` | `FF`, `FE` | 2 | 3 (sau `abc`) | `abc��def` (2 ký tự `U+FFFD`) |
| 2 | `/img?name=ab` (12 byte) rồi `FF` (từ `%FF`) rồi `cd` | `FF` | 1 | 12 | `/img?name=ab�cd` |
| 3 | `caf` `C3` | `C3` (thiếu byte nối) | 1 | 3 | `caf�` |
| 4 | `a` `00` `b` `FF` `c` | `FF` (NUL hợp lệ trong UTF-8) | 1 | 3 | `a<NUL>b�c` |
| 5 | `hello` | không | — | — | `hello` (`OK`) |

- Packet 4: 1 byte NUL trong 5 byte là 20%, dưới ngưỡng nhị phân 30% (`BINARY_NUL_RATIO`), nên nội dung không bị bỏ qua (`SKIPPED`) mà vẫn bị đánh dấu lỗi.
- Mỗi byte lỗi thay bằng đúng một ký tự `U+FFFD` (đếm chính xác bằng `errors="surrogateescape"`, không dùng `ignore` để khỏi mất dấu hiệu).
- Packet 1–4: `decoded_fields.<body|uri>.status="PARTIAL"`, `charset="utf-8"`; `decode_status="PARTIAL"`, `preprocess_status="partial"`.
- Packet 2: `app_fields.uri` vẫn là `/img?name=ab%FFcd` (raw còn nguyên); `encodings=["percent"]`.
- Packet 5: `OK`, `decode_status="OK"`, `preprocess_status="valid"` → chương trình tiếp tục xử lý sau các packet lỗi; số event = 5.

## Kết quả thực tế
`pytest .../T04_invalid_bytes`: 17 passed. Đối chiếu `events.jsonl` (5 event, đều `status="OK"`, `app_protocol="HTTP"`, `error_info=null`):

| Packet | Trường | `value` | `status` | `invalid_byte_count` | `first_invalid_offset` |
|---|---|---|---|---|---|
| 1 | `decoded_fields.body` | `abc��def` | `PARTIAL` | 2 | 3 |
| 2 | `decoded_fields.uri` | `/img?name=ab�cd` | `PARTIAL` | 1 | 12 |
| 3 | `decoded_fields.body` | `caf�` | `PARTIAL` | 1 | 3 |
| 4 | `decoded_fields.body` | `a\u0000b�c` | `PARTIAL` | 1 | 3 |
| 5 | `decoded_fields.body` | `hello` | `OK` | — | — |

- Packet 1–4: `charset="utf-8"`, `decode_status="PARTIAL"`, `preprocess_status="partial"`; số ký tự `U+FFFD` bằng đúng `invalid_byte_count`.
- Packet 2: `app_fields.uri` = `/img?name=ab%FFcd` (raw còn nguyên), `encodings=["percent"]`; GET nên có thêm `decoded_fields.body` = `SKIPPED` (`empty_payload`).
- Packet 4: 1 byte NUL trong 5 byte (20%) dưới ngưỡng nhị phân 30% nên không bị `SKIPPED`.
- Packet 5 (sau 4 packet lỗi) vẫn `OK`, `decode_status="OK"`, `preprocess_status="valid"`: chương trình tiếp tục chạy; số event = 5.
- `app_fields.body_preview` chứa `�` vì parser Bài 1 dùng `errors="replace"`; byte gốc nằm trong `input.pcap`, không nằm trong log.
- Độ dài khớp tính tay: `body_offset` 104 + `content_length` = `payload_byte_count` (112, 108, 109, 109); `raw_length` = 54 + payload.
- `processing_action="normalized"` ở cả 5 event vì tên header `Host`, `Content-Type`, `Content-Length` được hạ chữ thường.
- `flows.jsonl`: 5 flow (cổng nguồn 40031–40035), mỗi flow `packet_count=1`, `close_reason="flush"`, `midstream=true`.
- Không có key `payload` trong log; không crash.

## Kết luận
PASS