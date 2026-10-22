# T08 – Bidirectional flow

## Input
`input.pcap`, 8 gói TCP, port server 80:
- Kết nối A (client 10.0.0.1:40201): SYN, SYN/ACK, ACK, request `GET /index.html` (47 byte),
  response `200 OK` (43 byte), ACK.
- Kết nối B (client port 40202): capture bắt đầu từ response của server (43 byte), sau đó là ACK của client.

## Kết quả mong đợi (tính tay)
raw_length: gói không payload = 14 + 20 + 20 = 54; request = 54 + 47 = 101; response = 54 + 43 = 97.

| Gói | Hướng | flow_state | raw_length |
|---|---|---|---|
| 1 SYN | forward | HANDSHAKE | 54 |
| 2 SYN/ACK | backward | HANDSHAKE | 54 |
| 3 ACK | forward | ESTABLISHED | 54 |
| 4 request | forward | ESTABLISHED | 101 |
| 5 response | backward | ESTABLISHED | 97 |
| 6 ACK | forward | ESTABLISHED | 54 |
| 7 response (gói đầu của B) | forward | ESTABLISHED | 97 |
| 8 ACK | backward | ESTABLISHED | 54 |

Có 2 flow; mọi gói của cùng một kết nối (cả hai chiều) có cùng `flow_id`.

| Flow | endpoint_a | packets (fwd/bwd) | byte (fwd/bwd) | payload | syn / ack | midstream | duration |
|---|---|---|---|---|---|---|---|
| A | 10.0.0.1:40201 | 6 (4/2) | 414 (263/151) | 90 | 2 / 5 | false | 5.0 |
| B | 10.0.0.2:80 | 2 (1/1) | 151 (97/54) | 43 | 0 / 2 | true | 1.0 |

Cả hai: `application_protocol=HTTP`, `state=ESTABLISHED`, `close_reason=flush`, fin=rst=0.

## Kết quả thực tế
- `events.jsonl`: 8 event, tất cả `status=OK`. Gói 4 (request) và 5, 7 (response) có
  `app_protocol=HTTP`, `detection_method=port+payload`, `decode_status=OK`, `processing_action=normalized`
  (header name hạ chữ thường vào `headers_normalized`). Các gói còn lại không có payload nên `app_protocol=null`,
  `processing_action=defaults_filled` (giống T06/T07).
  `raw_length`: 54 / 101 (gói 4) / 97 (gói 5, 7). `payload_length` của event = 20 + payload ứng dụng (67, 63).
  `direction`/`flow_state` từng gói trùng bảng mong đợi.
- `flows.jsonl`: 2 flow.
  - A (56d6879e1bab7e0e): endpoint_a=10.0.0.1:40201, packet 6 (4/2), byte 414 (263/151), payload 90,
    syn 2, ack 5, HTTP, ESTABLISHED, midstream=false, duration 5.0, close_reason=flush.
  - B (00b7288aad5ec473): endpoint_a=10.0.0.2:80, packet 2 (1/1), byte 151 (97/54), payload 43,
    syn 0, ack 2, HTTP, ESTABLISHED, midstream=true, duration 1.0, close_reason=flush.

## Kết luận
**PASS** – khớp 100% giá trị tính tay.
- Hai chiều của cùng một kết nối dùng chung `flow_id`; `fwd_*`/`bwd_*` tách đúng theo chiều.
- Flow B bắt đầu bằng gói của server nên `endpoint_a` là server và `direction` tính theo `endpoint_a`
  (gói 7 = forward, gói 8 = backward); flow được đánh dấu `midstream=true` vì không thấy handshake.
- `application_protocol` của flow lấy từ gói HTTP và được giữ nguyên khi gặp gói ACK không có app protocol.
- `payload_byte_count` (90, 43) chỉ đếm payload ứng dụng, khác `payload_length` của event.