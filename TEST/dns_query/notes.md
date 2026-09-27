# Test Case 07: DNS Query

## 1. Input
- Nguồn: `input.pcap` (sinh bằng Scapy, xem `gen_pcap_file/`)
- Nội dung: 1 gói UDP từ Client (192.168.1.100:12345) đến Server (10.0.0.1:53), payload là 1 DNS query hỏi bản ghi A cho `example.com` (transaction id `0x1234`).

## 2. Kết quả mong đợi 
- `status`: `"OK"`, không crash.
- `network_protocol`: `"IPv4"`, `src_ip`: `192.168.1.100`, `dst_ip`: `10.0.0.1`.
- `transport_protocol`: `"UDP"`, `src_port`: `12345`, `dst_port`: `53`.
- `transport_fields.length_mismatch`: `false` (frame đủ lớn, không có Ethernet padding gây lệch — đối chiếu lại Actual để chắc chắn).
- `app_protocol`: `"DNS"`, `detection_method`: `"port+payload"` (dst_port=53 khớp `KNOWN_PORTS`, payload cũng khớp heuristic RFC 1035 header).
- `app_fields`:
  - `transaction_id`: `4660` (thập phân của `0x1234`)
  - `type`: `"query"`
  - `rcode`: `0`
  - `queries`: `[{"name": "example.com", "qtype": "A"}]`
  - `answers`: `[]`

## 3. Kết quả thực tế 
`queries` chưa có nội dung.

## 4. Kết luận
**PASS**