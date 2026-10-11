# T06 — Missing field (case 01)

Hai nửa: (A) 2 packet TCP không có payload trong `input.pcap`; (B) 8 event tổng hợp trong `test_t06_missing_field.py` (đi qua `run_events`), vì event thiếu field không thể xuất phát từ pcap.

## Input
**A. `input.pcap`:** (1) TCP SYN không payload; (2) TCP ACK thuần không payload (biến thể).
**B. Event tổng hợp:** chỉ có 5 field bắt buộc (`packet_id`, `timestamp`, `src_ip`, `dst_ip`, `network_protocol`) cộng thêm tuỳ trường hợp: `min_tcp`, `min_udp`, container bằng `None`, container sai kiểu (`"x"`, `["x"]`, `5`), `http_empty` (`app_protocol="HTTP"` không có `app_fields`), `dns_empty`, `no_transport` (không có tầng giao vận), `no_src_port` (TCP thiếu `src_port`).

## Kết quả mong đợi
Quy ước: container thiếu hoặc sai kiểu → `{}`; danh sách thiếu → `[]`; số/chuỗi thiếu → `null`; TCP luôn có `flags` (danh sách, mặc định `[]`); UDP **không có** khóa `flags`.

| Trường hợp | `preprocess_status` | `processing_action` | Kết quả |
|---|---|---|---|
| A1: SYN, A2: ACK (pcap) | `valid` | `defaults_filled` | `app_fields={}`, `decoded_fields={}`, `reason=[]`, `flags=["SYN"]`/`["ACK"]` |
| `min_tcp` | `valid` | `defaults_filled` | `transport_fields={"flags":[]}`; mọi container `{}`; `app_protocol=null` |
| `min_udp` | `valid` | `none` | `transport_fields={}` (không có `flags`) |
| container `None` | `valid` | `defaults_filled` | thay bằng `{}`/`[]`, TCP có `flags=[]` |
| container sai kiểu | `valid` | `defaults_filled` | thay bằng `{}`, Preprocessor không phát sinh lỗi (`error_info.layer != "preprocessor"`) |
| `http_empty` | `valid` | `defaults_filled` | `app_fields={"headers":{}, "header_pairs":[]}` |
| `dns_empty` | `valid` | `defaults_filled` | `app_fields={"queries":[], "answers":[]}` |
| `no_transport` | `partial` | `none` | `reason=["missing_transport"]` (thiếu tầng giao vận chỉ là suy giảm) |
| `no_src_port` | `invalid` | `flagged` | `reason=["missing_src_port"]` (cổng là field **bắt buộc**, đối chiếu) |

- Thiếu field **không bắt buộc** không bao giờ làm event `invalid`; không có exception; mọi kết quả serialize được thành JSON (không có giá trị lạ).

## Kết quả thực tế
(điền sau khi chạy)

## Kết luận
PASS / FAIL