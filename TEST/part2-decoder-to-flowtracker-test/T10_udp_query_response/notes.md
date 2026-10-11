# T10 – UDP query/response

## Input
`input.pcap`, 4 gói UDP/DNS (client 10.0.0.1 → resolver 10.0.0.53:53):
- Trao đổi 1 (client port 53011): query `www.example.com` (A) và response có 1 bản ghi A `93.184.216.34`.
- Trao đổi 2 (client port 53012, biến thể phụ): query `nonexistent.example.org` (AAAA) và response NXDOMAIN, không có answer.

## Kết quả mong đợi (tính tay)
Độ dài frame = 14 (Ethernet) + 20 (IP) + 8 (UDP) + DNS; **đã đối chiếu lại bằng Scapy đọc từ pcap**:

| Gói | Nội dung | DNS bytes | Frame |
|---|---|---|---|
| 1 | query A | 33 | 75 |
| 2 | response A | 64 (33 + bản ghi 31) | 106 |
| 3 | query AAAA | 41 | 83 |
| 4 | response NXDOMAIN | 41 | 83 |

Mọi event: `transport_protocol=UDP`, `app_protocol=DNS`, `flow_state=ACTIVE`, không có `flags`; direction F,B,F,B.

| Flow | endpoint_a | packets (fwd/bwd) | byte (fwd/bwd) | duration |
|---|---|---|---|---|
| 1 (53011) | 10.0.0.1:53011 | 2 (1/1) | 181 (75/106) | 0.5 |
| 2 (53012) | 10.0.0.1:53012 | 2 (1/1) | 166 (83/83) | 0.25 |

Cả hai: `protocol=UDP`, `application_protocol=DNS`, `state=ACTIVE`, syn=ack=fin=rst=0, `midstream=false`, `close_reason=flush`.

## Kết quả thực tế
- `events.jsonl`: 4 event, tất cả `status=OK`, `transport_protocol=UDP`, `app_protocol=DNS`,
  `detection_method=port+payload`, `flow_state=ACTIVE`, `decode_status=SKIPPED`,
  `preprocess_status=valid`, `processing_action=none`. `transport_fields` chỉ có `length`/`length_mismatch` (không có `flags`).
  `raw_length` = 75 / 106 / 83 / 83; `direction` = forward / backward / forward / backward.
  - Gói 1: query `www.example.com` A. Gói 2: response có answer A `93.184.216.34`.
  - Gói 3: query `nonexistent.example.org` AAAA. Gói 4: response `rcode=3` (NXDOMAIN), `answers=[]`.
- `flows.jsonl`: 2 flow UDP.
  - dbc9997b5c2e6653 (53011): packet 2 (1/1), byte 181 (75/106), payload 97, duration 0.5.
  - c565810ed8752584 (53012): packet 2 (1/1), byte 166 (83/83), payload 82, duration 0.25.
  - Cả hai: application_protocol=DNS, state=ACTIVE, syn=ack=fin=rst=0, midstream=false, close_reason=flush.

## Kết luận
**PASS** – khớp 100% giá trị tính tay và khớp độ dài frame đọc lại từ pcap bằng Scapy.
- Query và response dùng chung `flow_id` (đảo chiều port vẫn cùng một flow), direction forward/backward đúng.
- `byte_count` của flow = tổng frame gồm Ethernet header; `payload_byte_count` (97, 82) = đúng số byte DNS (33+64, 41+41).
- `transport_fields["length"]` = 8 + DNS bytes (41, 72, 49, 49), cũng là `payload_length` của event.
- Khác với gói TCP không payload, event DNS có đủ container nên `processing_action=none` (không cần điền mặc định).
- Response NXDOMAIN (không có answer) được parse bình thường, không bị đánh `partial`.