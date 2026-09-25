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
- [ ] Thu thập packet — live capture + PCAP import 
- [ ] Parser tầng Network & Transport — IPv4, TCP, UDP 
- [ ] Nhận diện & parser tầng Application — HTTP, DNS, SMTP 
- [ ] Tích hợp pipeline hoàn chỉnh 
- [ ] Chạy đủ các test case bắt buộc 

> Phần "Cách chạy" bên dưới mô tả cách sử dụng module **sau khi hoàn thành**; hiện tại `main.py` và pipeline xử lý chưa được tích hợp đầy đủ.

## Cách chạy

**1. Set up môi trường:**

```bash
pip install -r requirements.txt
```

**2. Packet Capture:**

**2.1. Live capture từ một network interface:**

```bash
sudo python main.py --interface eth0
```

**2.2. Import và xử lý packet từ file PCAP:**

```bash
python main.py --pcap test.pcap
```

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
├── config/ # File cấu hình module (mapping port cho từng application protocol, policy xử lý protocol không xác định...), tách riêng khỏi code.
└── TEST/ # Kết quả các test case bắt buộc: input dùng để test, output thực tế, và ghi chú đánh giá pass/fail cho từng test case.
```

Cấu trúc này được thiết kế để mở rộng cho các bài tập tiếp theo trong cùng repo: mỗi module IDS mới (feature extraction, phát hiện port scan, cảnh báo...) sẽ được thêm vào như một thành phần song song trong `src/`, dùng chung schema `IDSEvent` mà module này tạo ra.