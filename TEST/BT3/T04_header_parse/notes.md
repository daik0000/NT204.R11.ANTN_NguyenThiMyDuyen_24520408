# T04 – Phân tích header của rule

## Mục tiêu
Header `action proto src_ip src_port direction dst_ip dst_port` được đọc thành đúng đối tượng `Rule`: địa chỉ IPv4 và CIDR lưu dạng số nguyên (network + mask), cổng đơn/dải về dạng `(lo, hi)`, host bit trong CIDR bị xoá, `any` là một cờ, `protocol` và `direction` đúng.

## Input
- `rules.rules`: 4 rule chỉ có header (không `content`, không option khác) — các rule của đề.
- `variants.rules`: 4 rule biến thể (protocol `ip`, cổng đơn viết thành dải, `/32`, `/0`, giá trị lớn nhất của địa chỉ và cổng).
- `input.pcap` (do `make_pcap.py` dựng, md5 cố định `a0a7501d54ef7c25a6725df2e9373046`): một gói SYN `10.0.0.5:40004 -> 192.168.1.9:80`, chỉ để `main.py` chạy và cho thấy header đã phân tích hoạt động đúng (việc khớp được kiểm kỹ ở T05).
- Cách nạp: bài test chạy `main.py` với hai tuỳ chọn `--rules`, theo thứ tự `rules.rules` rồi `variants.rules`; cấu hình tạm có `engine.rule_files: []` nên không có rule mẫu nào khác bị nạp.

## Kết quả mong đợi (tính tay trước khi chạy)
Cách tính: `a.b.c.d = a·2²⁴ + b·2¹⁶ + c·2⁸ + d`; mặt nạ `/n` có `n` bit 1 đứng đầu.

| Địa chỉ | Giá trị | Mặt nạ |
|---|---|---|
| `10.0.0.5` | 167772160 + 5 = **167772165** | `/32` = `0xFFFFFFFF` |
| `192.168.1.0/24` | 3221225472 + 11010048 + 256 = **3232235776** | `0xFFFFFF00` |
| `10.0.0.0/8` | **167772160** | `0xFF000000` |
| `10.0.0.5/24` | host bit bị xoá → 10.0.0.0 = **167772160** | `0xFFFFFF00` |
| `172.16.0.0/12` | 2885681152 + 1048576 = **2886729728** | `0xFFF00000` |
| `255.255.255.255` | **4294967295** | `0xFFFFFFFF` |
| `192.168.1.77/32` | 3232235776 + 77 = **3232235853** (`0xC0A8014D`) | `0xFFFFFFFF` |
| `10.0.0.0/30` | 167772160 | `0xFFFFFFFC` |

Cổng: `80` → (80, 80); `1:1024` → (1, 1024); `:1023` → (0, 1023); `5000:` → (5000, 65535); `any` và `0:65535` → (0, 65535) (`is_any`); `80:80` → (80, 80); `0:0` → (0, 0); `65535` → (65535, 65535).

`rules.rules`:

| sid | protocol | src_ip | src_port | direction | dst_ip | dst_port |
|---|---|---|---|---|---|---|
| 4001 | tcp | any | any | `->` | any | (80, 80) |
| 4002 | tcp | 167772165 / 0xFFFFFFFF | any | `->` | 3232235776 / 0xFFFFFF00 | (1, 1024) |
| 4003 | udp | 167772160 / 0xFF000000 | (0, 1023) | `->` | any | (5000, 65535) |
| 4004 | tcp | 167772160 / 0xFFFFFF00 | any | `<>` | any | any |

`variants.rules`:

| sid | protocol | src_ip | src_port | dst_ip | dst_port |
|---|---|---|---|---|---|
| 4101 | ip | any | any | any | any |
| 4102 | tcp | 3232235853 / 0xFFFFFFFF | (80, 80) | 167772160 / 0xFFFFFFFC | (0, 0) |
| 4103 | tcp | 0 / 0 (`0.0.0.0/0`, không phải `any`) | (0, 65535) = any | any | any |
| 4104 | udp | 2886729728 / 0xFFF00000 | any | 4294967295 / 0xFFFFFFFF | (65535, 65535) |

Mọi rule: `action = alert`, `contents = ()` (rule chỉ có header), `flow = flags = dsize = None`, `classtype = None`, `rev = 1`, `priority = 3` (mặc định). Cả 8 rule `valid`; `rule_lines = 8`, `comment = 2`, `total_lines = 10`.

Gói SYN `10.0.0.5:40004 -> 192.168.1.9:80` (TCP) với các header đã phân tích:
- 4001 có (đích cổng 80); 4002 có (nguồn đúng 10.0.0.5, đích trong 192.168.1.0/24, cổng 80 ∈ 1:1024); 4003 không (UDP); 4004 có (10.0.0.5 ∈ 10.0.0.0/24, `any` đích); 4101 có (`ip` khớp mọi gói TCP/UDP); 4102 không (nguồn là 192.168.1.77); 4103 có (`0.0.0.0/0` khớp mọi IP); 4104 không (UDP).
- Vậy `detections.jsonl` có 5 Detection theo thứ tự rule: sid 4001, 4002, 4004, 4101, 4103, mỗi cái `matched = [{"keyword": "header"}]`, `packet_id = 1`.
- Không có cảnh báo `rejected` nào.

## Kết quả thực tế
Chạy `pytest TEST/BT3/T04_header_parse`: **19 test pass**, mọi giá trị khớp bảng tính tay (không phải sửa kỳ vọng).

- `Rule` của cả 8 rule có đúng từng field `protocol`, `src_ip`, `src_port`, `direction`, `dst_ip`, `dst_port` như hai bảng trên; `10.0.0.5/24` ra `167772160 / 0xFFFFFF00`; `:1023` ra (0, 1023); `5000:` ra (5000, 65535).
- `contents == ()`, `rev = 1`, `priority = 3`, các option khác `None`; `source_file`, `line_no`, `raw` khớp dòng trong file.
- `rules_report.jsonl`: 8 dòng, đều `valid`, `reason: null`, sid 4001–4004, 4101–4104.
- `detections.jsonl`: 5 dòng, sid 4001, 4002, 4004, 4101, 4103 như đã tính; `events.jsonl` 1 event; `flows.jsonl` 1 flow; `main.py` exit 0.
- `input.pcap` dựng lại cho cùng md5; chạy hai lần liên tiếp cho output giống hệt từng byte.

## Bằng chứng trong thư mục
`rules_report.jsonl`, `events.jsonl`, `flows.jsonl`, `detections.jsonl` do `main.py` ghi (qua `run_case_ids`), sinh lại mỗi lần chạy, không sửa tay; trường `file` là đường dẫn tương đối so với gốc repo. Không có `warnings.txt` vì không rule nào bị loại.

## Kết luận
**PASS.**

Chạy: `pytest TEST/BT3/T04_header_parse`.
