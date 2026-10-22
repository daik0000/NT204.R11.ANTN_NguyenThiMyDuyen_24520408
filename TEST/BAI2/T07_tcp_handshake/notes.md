# T07 – TCP handshake

## Input
`input.pcap`, 7 gói TCP không payload (10.0.0.1 → 10.0.0.2:80):
- Kết nối A (port 40101): SYN → SYN/ACK → ACK
- Kết nối B (port 40102): SYN → SYN (gửi lại) → SYN/ACK → ACK

## Kết quả mong đợi (tính tay)
| Gói | Flags | Hướng | flow_state |
|---|---|---|---|
| 1 | SYN | forward | HANDSHAKE |
| 2 | SYN,ACK | backward | HANDSHAKE |
| 3 | ACK | forward | ESTABLISHED |
| 4 | SYN | forward | HANDSHAKE |
| 5 | SYN (retransmit) | forward | HANDSHAKE (không đổi) |
| 6 | SYN,ACK | backward | HANDSHAKE |
| 7 | ACK | forward | ESTABLISHED |

Mỗi gói `raw_length = 14 + 20 + 20 = 54`. Có đúng 2 flow.

| Flow | packets (fwd/bwd) | syn_count | ack_count | byte_count | duration |
|---|---|---|---|---|---|
| A (40101) | 3 (2/1) | 2 (SYN, SYN/ACK) | 2 (SYN/ACK, ACK) | 162 | 2.0 |
| B (40102) | 4 (3/1) | 3 (SYN, SYN, SYN/ACK) | 2 (SYN/ACK, ACK) | 216 | 3.0 |

Cả hai flow: `state=ESTABLISHED`, `close_reason=flush`, `midstream=false`, `fin_count=rst_count=0`, `endpoint_a` = client.

## Kết quả thực tế
- `events.jsonl`: 7 event, tất cả `status=OK`, `transport_protocol=TCP`, `raw_length=54`,
  `decode_status=SKIPPED`, `preprocess_status=valid`, `processing_action=defaults_filled`.
  `flow_state`/`direction` từng gói trùng bảng mong đợi (HANDSHAKE, HANDSHAKE, ESTABLISHED cho A;
  HANDSHAKE, HANDSHAKE, HANDSHAKE, ESTABLISHED cho B).
- `flows.jsonl`: 2 flow.
  - A (f368f576a63ecfea): packet 3 (2/1), syn 2, ack 2, byte 162 (108/54), duration 2.0.
  - B (15d793eb6dc16c71): packet 4 (3/1), syn 3, ack 2, byte 216 (162/54), duration 3.0.
  - Cả hai: state=ESTABLISHED, close_reason=flush, midstream=false, fin=rst=0,
    payload_byte_count=0, application_protocol=null.

## Kết luận
**PASS** – khớp 100% giá trị tính tay.
- Handshake 3 bước đi đúng HANDSHAKE → HANDSHAKE → ESTABLISHED; SYN/ACK không làm flow ESTABLISHED sớm.
- SYN retransmit vẫn thuộc cùng flow, cùng direction forward, tăng `syn_count` nhưng giữ nguyên HANDSHAKE.
- Hai kết nối cùng IP, khác source port thành hai flow riêng với flow_id khác nhau.
- Ghi chú: `processing_action=defaults_filled` ở mọi gói do không có payload (giống T06);
  `payload_length` của event (20, gồm TCP header) khác `payload_byte_count` của flow (0, chỉ payload ứng dụng).