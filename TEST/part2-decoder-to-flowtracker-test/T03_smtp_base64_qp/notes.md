# T03 — SMTP Base64 / Quoted-Printable (case 01)

## Input
`input.pcap` (tạo bằng `make_pcap.py`, 5 packet TCP → cổng 25, timestamp cố định). Mỗi packet là nội dung thư (DATA): header MIME, dòng trống, body, rồi marker kết thúc `\r\n.\r\n`:
1. `Content-Transfer-Encoding: base64`, body `Q2Fmw6kgSURT`
2. `Content-Transfer-Encoding: quoted-printable`, body `Xin ch=C3=A0o caf=C3=A9, 1+1=3D2, soft=` + xuống dòng + `break`
3. `base64`, body `SGVs!bG8` (biến thể: có ký tự lạ và thiếu padding)
4. `base64`, body `A` (biến thể: không thể giải mã)
5. Header `Content-Transfer-Encoding:  BASE64 ` (biến thể: viết hoa, thừa khoảng trắng), body `SGVsbG8gV29ybGQ=`

## Kết quả mong đợi (tính tay)
**Packet 1 (Base64):** mỗi nhóm 4 ký tự → 3 byte: `Q2Fm`→`43 61 66`="Caf"; `w6kg`→`C3 A9 20`= "é" (UTF-8) + khoảng trắng; `SURT`→`49 44 53`="IDS" → **`Café IDS`**.

**Packet 2 (QP):** `=C3=A0`→`à`; `=C3=A9`→`é`; `=3D`→`=`; `=` ở cuối dòng (soft line break) → nối hai dòng, bỏ xuống dòng → **`Xin chào café, 1+1=2, softbreak`**.

**Packet 3:** loại `!` và bù padding → `SGVsbG8` → `Hello`, nhưng vì có sửa → `PARTIAL`, `reason="malformed_base64_cleaned"`.
**Packet 4:** một ký tự lẻ không tạo thành byte nào → `FAILED`, `reason="base64_decode_failed"`, giá trị giữ nguyên raw `A`.
**Packet 5:** `SGVsbG8gV29ybGQ=` → **`Hello World`**; header vẫn được nhận ra dù viết `BASE64`.

| Packet | `decoded_fields.body.status` | `decode_status` (event) | `preprocess_status` |
|---|---|---|---|
| 1, 2, 5 | `OK` | `OK` | `valid` |
| 3 | `PARTIAL` | `PARTIAL` | `partial` |
| 4 | `FAILED` | `FAILED` | `partial` |

- `encodings`: `["base64"]` (1, 3, 5) và `["quoted-printable"]` (2).
- Marker `\r\n.\r\n` không nằm trong giá trị đã giải mã.
- Packet lỗi (3, 4) không làm dừng chương trình: packet 5 vẫn được xử lý đúng; số event = 5.
- `app_fields.mime_headers["content-transfer-encoding"]` của packet 5 giữ nguyên chữ hoa `BASE64` (header gốc không bị sửa).

## Kết quả thực tế
`pytest .../T03_smtp_base64_qp`: 20 passed. Đối chiếu `events.jsonl` (5 event, đều `status="OK"`, `app_protocol="SMTP"`, `app_fields.type="data"`, `detection_method="port"`, `error_info=null`):

| Packet | `decoded_fields.body.value` | `status` | `encodings` | `reason` | `decode_status` | `preprocess_status` |
|---|---|---|---|---|---|---|
| 1 | `Café IDS` | `OK` | `["base64"]` | — | `OK` | `valid` |
| 2 | `Xin chào café, 1+1=2, softbreak` | `OK` | `["quoted-printable"]` | — | `OK` | `valid` |
| 3 | `Hello` | `PARTIAL` | `["base64"]` | `malformed_base64_cleaned` | `PARTIAL` | `partial` |
| 4 | `A` (giữ nguyên raw) | `FAILED` | (không có) | `base64_decode_failed` | `FAILED` | `partial` |
| 5 | `Hello World` | `OK` | `["base64"]` | — | `OK` | `valid` |

- Packet 3 và 4 hỏng nhưng chương trình vẫn xử lý tiếp: packet 5 giải mã đúng; số event = 5.
- Marker `\r\n.\r\n` không nằm trong giá trị giải mã.
- Packet 5: `mime_headers["content-transfer-encoding"]` vẫn là `BASE64` (giữ nguyên chữ hoa), nhưng decoder nhận ra là Base64 (`encodings=["base64"]`).
- Độ dài khớp tính tay: `body_offset` + body + 5 (marker) = `payload_byte_count` của flow (97+12+5=114, 107+46+5=158, 97+8+5=110, 97+1+5=103, 99+16+5=120); `raw_length` = 54 + payload.
- `processing_action="none"` cả 5 event: Preprocessor không có gì để chuẩn hoá trong nội dung thư.
- `flows.jsonl`: 5 flow (cổng nguồn 40021–40025 khác nhau), `application_protocol="SMTP"`, mỗi flow `packet_count=1`, `close_reason="flush"`, `midstream=true`.
- Không có key `payload` trong log; không crash.

## Kết luận
PASS