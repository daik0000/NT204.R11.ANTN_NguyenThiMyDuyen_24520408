# NT204.R11.ANTN_NguyenThiMyDuyen_24520408
## Mục tiêu

Đây là repo bài tập lớn cho môn học **Hệ thống tìm kiếm, phát hiện và ngăn chặn xâm nhập**. Toàn bộ các bài tập trong môn học sẽ được phát triển tiếp trên cùng repo này, theo hướng xây dựng dần một hệ thống **Intrusion Detection System (IDS)** hoàn chỉnh bằng Python.

Bài tập đầu tiên (module này) xây dựng tầng **Packet Capture & Parser** - nền tảng cho toàn bộ các module IDS phía sau (feature extraction, port-scan detection, alerting...). Module có nhiệm vụ:

- Thu thập lưu lượng mạng từ **live traffic** (bắt trực tiếp trên network interface) hoặc từ **file PCAP** có sẵn, thông qua cùng một pipeline xử lý duy nhất.
- Phân tích các gói tin theo các giao thức được hỗ trợ:
  - Network: IPv4
  - Transport: TCP, UDP
  - Application: HTTP/1.x, DNS, SMTP
- Chuyển mỗi gói tin thành một **cấu trúc dữ liệu chuẩn hóa** (normalized IDS event), để các module IDS phía sau xử lý mà không cần truy cập trực tiếp vào raw packet hay object của thư viện capture.
- Đảm bảo không crash khi gặp packet lỗi, thiếu header, payload rỗng, hoặc protocol không được hỗ trợ.
- Ghi lại toàn bộ kết quả parse ra file theo định dạng JSON Lines, để tái sử dụng ở các bài tập tiếp theo.

## Trạng thái hiện tại

- [x] Khởi tạo project, cấu trúc thư mục (Issue #1)
- [x] Chuẩn hóa schema dữ liệu sự kiện (`IDSEvent`) và JSON Lines logger (Issue #3)
- [x] Thu thập packet — live capture + PCAP import (Issue #4)
- [ ] Parser tầng Network & Transport — IPv4, TCP, UDP 
- [ ] Nhận diện & parser tầng Application — HTTP, DNS, SMTP 
- [ ] Tích hợp pipeline hoàn chỉnh 
- [ ] Chạy đủ các test case bắt buộc 

> Ở giai đoạn này, `main.py` đã chạy được và in số lượng gói tin thu thập ra log (chưa parse nội dung packet). 

## Cách chạy

Môi trường: Linux, Python 3.10+.

```bash
pip install -r requirements.txt
```

Live capture từ một network interface (cần quyền root):

```bash
sudo python main.py --interface eth0
```

Live capture với BPF filter tùy chỉnh ở tầng kernel (mặc định là `"tcp or udp"`):

```bash
sudo python main.py --interface eth0 --bpf-filter "tcp port 80"
```

Import và xử lý packet từ file PCAP (tham số `--bpf-filter` không áp dụng cho chế độ này):

```bash
python main.py --pcap test.pcap
```

> Lưu ý: live capture cần quyền root (hoặc cấp quyền `cap_net_raw` cho Python) để có thể mở interface ở chế độ bắt gói tin trực tiếp. Nhấn `Ctrl+C` để dừng chế độ `--interface`.

### Tối ưu buffer OS cho live capture

Khi capture traffic thật với tốc độ cao, buffer socket mặc định của Linux có thể không đủ lớn, dẫn đến mất gói tin (packet loss) ở tầng kernel trước khi packet kịp lên tới Python. Có thể tăng buffer bằng:

```bash
sudo sysctl -w net.core.rmem_max=26214400
sudo sysctl -w net.core.rmem_default=26214400
```

Hai giá trị trên chỉ có hiệu lực cho phiên làm việc hiện tại; để giữ lại sau khi khởi động lại máy, thêm 2 dòng tương ứng vào `/etc/sysctl.conf` rồi chạy `sudo sysctl -p`.

## IDSEvent

Mỗi gói tin sau khi qua pipeline sẽ được chuẩn hóa thành một dòng JSON theo schema `IDSEvent` (định nghĩa tại `src/models/event.py`), gồm 4 nhóm field:

- **Định danh & thời gian**: `packet_id`, `timestamp`
- **Network layer**: `src_ip`, `dst_ip`, `network_protocol`, `network_fields` (chi tiết riêng của IPv4 như `ttl`, `header_length`)
- **Transport layer**: `src_port`, `dst_port`, `transport_protocol`, `transport_fields` (với TCP: `flags`, `seq`, `ack`, `window`; với UDP: `length`)
- **Application layer**: `app_protocol`, `detection_method` (`port`/`payload`/`port+payload`), `app_fields` (chi tiết riêng theo từng giao thức HTTP/DNS/SMTP)
- **Metadata**: `raw_length`, `payload_length`, `status` (`OK`/`UNKNOWN`/`MALFORMED`)

Đây là format dữ liệu duy nhất mà các module phía sau được phép sử dụng - không truy cập trực tiếp object của thư viện capture (Scapy). Kết quả được ghi liên tục ra file JSON Lines (mặc định `output/events.jsonl`) qua `src/logging/jsonl_logger.py`.

## Cấu trúc thư mục

```
.
├── README.md
├── requirements.txt
├── .gitignore
├── main.py  # CLI entrypoint: --interface / --pcap
├── src/
│   ├── models/
│   │   └── event.py # Dataclass IDSEvent — schema chuẩn hóa dữ liệu sự kiện
│   ├── logging/
│   │   └── jsonl_logger.py # JSONLLogger — ghi IDSEvent ra file JSON Lines
│   ├── capture/
│   │   ├── pcap_reader.py     # Đọc file PCAP theo generator, trả về (timestamp, raw_bytes)
│   │   └── live_capture.py    # Bắt live traffic qua producer-consumer queue, trả về (timestamp, raw_bytes)
├── config/ # File cấu hình module (mapping port cho từng application protocol, policy xử lý protocol không xác định...), tách riêng khỏi code.
└── TEST/ # Kết quả các test case bắt buộc: input dùng để test, output thực tế, và ghi chú đánh giá pass/fail cho từng test case.
```

Cấu trúc này được thiết kế để mở rộng cho các bài tập tiếp theo trong cùng repo: mỗi module IDS mới (feature extraction, phát hiện port scan, cảnh báo...) sẽ được thêm vào như một thành phần song song trong `src/`, dùng chung schema `IDSEvent` mà module này tạo ra.