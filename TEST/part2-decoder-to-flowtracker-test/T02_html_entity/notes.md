# T02 — HTML entity (case 01)

## Input
`input.pcap` (tạo bằng `make_pcap.py`, 4 packet TCP, timestamp cố định):
1. Response `200 OK`, `Content-Type: text/html; charset=utf-8`, body `&lt;script&gt;alert(1)&lt;/script&gt; &#x27;ok&#x27;`
2. `POST /comment`, `application/x-www-form-urlencoded`, body `c=%26lt%3Bb%26gt%3B&e=%26amp%3Blt%3B&n=1`
3. `GET /page?a=1&copy=2`
4. Response `text/html`, body `1 &lt; 2 &amp;&amp; 3 &gt; 2 &amp;lt;` (biến thể phụ)

## Kết quả mong đợi (tính tay)
| Giá trị | Bước 1 | Bước 2 | Kết quả |
|---|---|---|---|
| Body packet 1 | (không có percent) | `&lt;`→`<`, `&gt;`→`>`, `&#x27;` (0x27)→`'` | `<script>alert(1)</script> 'ok'` |
| Param `c` | `%26lt%3Bb%26gt%3B` → `&lt;b&gt;` | → `<b>` | `<b>` |
| Param `e` | `%26amp%3Blt%3B` → `&amp;lt;` | → `&lt;` (chỉ giải mã **một lần**) | `&lt;` |
| Param `n` | `1` | không đổi | `1` |
| Body packet 4 | (không có percent) | `&lt;`→`<`, `&amp;&amp;`→`&&`, `&gt;`→`>`, `&amp;lt;`→`&lt;` | `1 < 2 && 3 > 2 &lt;` |
| URI packet 3 | — | **không áp dụng** | `/page?a=1&copy=2` (không thành `©=2`) |

- `app_fields.body_preview` giữ nguyên chuỗi entity/percent gốc (packet 1, 2, 4).
- `decoded_fields.body.value` đúng như bảng; `encodings=["html_entity"]`.
- `decoded_fields.form_params.value` = `[["c","<b>"],["e","&lt;"],["n","1"]]`, `encodings=["percent","html_entity"]` (đúng thứ tự).
- `decoded_fields.uri.value` (packet 3) = `/page?a=1&copy=2`, không có `html_entity` trong `encodings`.
- `decode_status="OK"` cho cả 4 event; không crash.

## Kết quả thực tế
`pytest .../T02_html_entity`: 9 passed. Đối chiếu `events.jsonl` (4 event, đều `status="OK"`, `decode_status="OK"`, `error_info=null`, `preprocess_status="valid"`):

| Packet | Raw (`app_fields`) | Decoded (`decoded_fields`) | `encodings` |
|---|---|---|---|
| 1 (response `text/html`) | `body_preview` = `&lt;script&gt;alert(1)&lt;/script&gt; &#x27;ok&#x27;` | `body.value` = `<script>alert(1)</script> 'ok'` | `["html_entity"]` |
| 2 (POST form) | `body_preview` = `c=%26lt%3Bb%26gt%3B&e=%26amp%3Blt%3B&n=1` | `form_params.value` = `[["c","<b>"],["e","&lt;"],["n","1"]]` | `["percent","html_entity"]` |
| 3 (GET) | `uri` = `/page?a=1&copy=2` | `uri.value` = `/page?a=1&copy=2` | (không có, không có `html_entity`) |
| 4 (response `text/html`) | `body_preview` = `1 &lt; 2 &amp;&amp; 3 &gt; 2 &amp;lt;` | `body.value` = `1 < 2 && 3 > 2 &lt;` | `["html_entity"]` |

- Thứ tự giải mã: param `c` đi từ `%26lt%3Bb%26gt%3B` → `&lt;b&gt;` (percent) → `<b>` (entity).
- Entity chỉ giải mã một lần: `e` và `&amp;lt;` (packet 4) dừng ở `&lt;`, không thành `<`.
- URI `?a=1&copy=2` không bị biến thành `©=2`; packet 3 chỉ có `decoded_fields.uri`, không qua bước entity.
- Packet 3 (GET) có `decoded_fields.body` = `SKIPPED` (`empty_payload`), không ảnh hưởng `decode_status`.
- Độ dài khớp tính tay: `body_offset + content_length` = `payload_byte_count` của flow (79+52=131, 114+40=154, 79+37=116); `raw_length` = 54 + payload HTTP.
- `flows.jsonl`: 4 flow (mỗi packet một cổng khác nhau), mỗi flow `packet_count=1`, `close_reason="flush"`, `midstream=true`. Hai flow của response có `endpoint_a` = `10.0.0.2:80` vì server là bên gửi packet đầu tiên.
- Không có key `payload` trong log; không crash.

Ghi chú: `path_normalized` chỉ giữ phần đường dẫn (`/comment`, `/page`), query không nằm trong trường này.

## Kết luận
PASS