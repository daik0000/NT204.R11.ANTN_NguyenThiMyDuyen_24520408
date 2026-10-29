# NT204.R11.ANTN_NguyenThiMyDuyen_24520408

Repo bài tập lớn môn **Hệ thống tìm kiếm, phát hiện và ngăn chặn xâm nhập**. Các bài tập được phát triển tiếp trên cùng repo, xây dựng dần một hệ thống **Intrusion Detection System (IDS)** bằng Python (Linux, Python 3.10+).

## Pipeline tổng quát

```
Capture (live / PCAP)
   -> Parser (IPv4, TCP/UDP, HTTP/DNS/SMTP)  -> IDSEvent chuẩn hóa
   -> Decoder          (giải mã percent-encoding, HTML entity, MIME)
   -> Preprocessor     (kiểm tra hợp lệ, chuẩn hóa, điền mặc định)
   -> Flow Tracker     (gom gói hai chiều theo flow, trạng thái TCP, thống kê)
   -> Rule Engine      (so khớp rule, sinh Detection Event)
   -> events.jsonl / flows.jsonl / detections.jsonl
```

Mỗi gói tin đi qua một pipeline duy nhất, dù lấy từ live traffic hay từ file PCAP. Một gói lỗi không làm dừng chương trình.

## Mục tiêu từng phần

**Part 1 — Packet Capture & Parser.** Thu thập lưu lượng từ network interface hoặc file PCAP, phân tích theo IPv4, TCP/UDP, HTTP/1.x, DNS, SMTP và chuyển mỗi gói thành một `IDSEvent` chuẩn hóa để các module phía sau không phải đụng tới raw packet. Ghi kết quả ra JSON Lines.

**Part 2 — Decoder, Preprocessor & Flow/Connection Tracker.** Giải mã dữ liệu mã hóa trong HTTP/SMTP mà vẫn giữ nguyên dữ liệu gốc; kiểm tra hợp lệ và chuẩn hóa event (đánh dấu `valid`/`partial`/`invalid`); gom các gói hai chiều thành flow, theo dõi trạng thái kết nối TCP, hết hạn flow theo timeout và xuất thống kê từng flow.

**Part 3 — Core Engine & Snort Rule Matching.** Xây dựng Core Engine cho IDS dựa trên signature/rule. Engine nhận dữ liệu chuẩn hóa từ Preprocessor và thông tin trạng thái/thống kê từ Flow/Connection Tracker, sau đó so khớp với bộ rule trong phạm vi được hỗ trợ để sinh Detection Event. Signature nằm hoàn toàn trong file `.rules`, không hard-code trong source code. Trạng thái: đang thực hiện.

## Cách chạy

```bash
pip install -r requirements.txt

python main.py --pcap test.pcap                       # đọc file PCAP
sudo python main.py --interface eth0                  # bắt live (cần quyền root)
sudo python main.py --interface eth0 --bpf-filter "tcp port 80"
python main.py --pcap test.pcap --config config/settings.yaml \
    --events-output output/events.jsonl --flows-output output/flows.jsonl

pytest                                                # toàn bộ test
pytest TEST/BT3                                       # chỉ test Part 3
```

| Tham số | Mặc định | Ý nghĩa |
|---|---|---|
| `--pcap FILE` / `--interface IF` | (chọn một) | Nguồn packet; hai tham số loại trừ nhau |
| `--config FILE` | `config/settings.yaml` | File cấu hình; giá trị sai làm chương trình dừng với exit code 1 |
| `--events-output FILE` | `output/events.jsonl` | Nơi ghi `IDSEvent` |
| `--flows-output FILE` | `output/flows.jsonl` | Nơi ghi flow record khi flow kết thúc |
| `--bpf-filter EXPR` | `"tcp or udp"` | BPF filter, chỉ áp dụng cho `--interface` |

Khi kết thúc (hết pcap, `Ctrl+C` hoặc lỗi), chương trình luôn flush các flow còn lại ra `flows.jsonl`. Exit code là 0 khi chạy xong hoặc bị `Ctrl+C`, 1 khi lỗi.

Cấu hình (timeout, policy, `engine`, ...) nằm trong `config/settings.yaml` và được kiểm tra ngay khi khởi động.

## Cấu trúc thư mục

```
main.py                 # CLI
config/                 # settings.yaml, rules/ (rule mẫu)
src/
├── capture/ parsers/ models/ logging/ utils/   # Part 1
├── decoder/ preprocessor/ flow/                # Part 2
├── rules/ engine/                              # Part 3: nạp rule, lập chỉ mục, so khớp
└── pipeline/               # ghép các bước
TEST/
├── BAI1/  BAI2/  BT3/      # test case và unit test từng phần
└── helpers/                # dựng PCAP cho test
```

## Giới hạn đã biết

**Part 2 — Flow Tracker**

- Event-time chỉ tiến khi có packet mới: ở chế độ `--interface`, nếu traffic ngừng hẳn thì flow chưa hết hạn cho tới packet kế tiếp hoặc lúc thoát (`flush`). Hướng mở rộng: `capture_live` phát tín hiệu heartbeat khi hàng đợi rỗng.
- `sweep` duyệt toàn bảng O(n) mỗi `sweep_interval_sec`. Hướng cải tiến: hàng đợi ưu tiên theo thời điểm hết hạn.
- Packet đến muộn hơn `clock` (không đúng thứ tự) không làm flow hết hạn và không kéo `clock` lùi; flow đã bị xuất rồi không được "mở lại".
- `flows.jsonl` chỉ có dòng cho flow đã xuất. Nếu chương trình bị kill cưỡng bức (`SIGKILL`, mất điện) thì các flow còn trong bảng không được ghi.
- Parse từng packet độc lập: không ghép lại TCP, không giải nén gzip/chunked, không giải mã TLS.

**Part 3 — Rule Engine**

- Cú pháp rule hỗ trợ có giới hạn: IPv4 (địa chỉ đơn hoặc CIDR), cổng đơn/dải; không hỗ trợ biến `$VAR`, phủ định `!`, danh sách `[...]`, `pcre` và các keyword ngoài phạm vi (các rule này được báo là `unsupported`, không bị bỏ qua âm thầm). `any` và các cờ TCP phải viết đúng chữ (`any` chữ thường, `flags` chữ in hoa `FSRPAUCE` hoặc `0`).
- `flags`: `!` đứng trước chữ, `+` và `*` đứng sau chữ (`SA+`, `!SA`); mặt nạ (`SA,12`) là `unsupported`. Vị trí modifier theo tài liệu Snort chưa được đối chiếu, nên `flags:+SA` / `flags:*SA` hiện bị từ chối.
- Indexer chỉ lọc thô theo protocol và cổng đích; dải cổng được duyệt tuyến tính (hướng cải tiến: interval tree). Event không có cổng (ICMP, ARP, thiếu tầng transport) không có rule ứng viên.
- `dsize` đo payload của từng segment/datagram, không ghép lại luồng TCP (giống Snort). Gói TCP tới cổng 80 mang payload không phải HTTP bị Part 1 đánh `MALFORMED`, nên không tới được engine.
- `match_header` đổi IP của gói sang số nguyên mỗi lần thử một rule ứng viên, chưa phải một lần cho cả gói. Event có IP không hợp lệ không khớp rule nào, kể cả `any any`.
- Gói `RST` đến sau khi kết nối đã established có state `RESET` nên bị coi là `not_established` (Snort giữ `established`).
- Vai trò `to_server`/`to_client` của flow TCP không bắt đầu bằng SYN (và của flow UDP) được suy ra từ cổng, nên có thể sai khi cả hai cổng đều là cổng tạm. Khi flow đã bị xuất khỏi bảng, engine không đoán: mọi rule có `flow:` coi như không khớp.

## AI usage disclosure

Trong quá trình phát triển, Claude Sonnet 5.5 (Anthropic) được sử dụng như sau:

- **Bài 1 - Packet Capture**: vai trò **review code và đưa ra gợi ý chỉnh sửa** cho từng commit trước khi đưa lên repo - không viết thay toàn bộ code. Phần lớn code nộp bài do người thực hiện tự viết; Claude chỉ đọc lại, chỉ ra lỗi/rủi ro tiềm ẩn (ví dụ: sai lệch so với schema đã chốt, race condition, dữ liệu bị parse sai âm thầm) và đề xuất hướng sửa, việc quyết định áp dụng sửa nào do người thực hiện tự cân nhắc.
- **Bài 2 - Decoder, Preprocessor và Flow Tracker**: lập kế hoạch Issue/commit (timeline) cho Bài 2; review từng commit như ở Bài 1; với một số file, Claude đề xuất đoạn mã sửa kèm unit test để người thực hiện đối chiếu, tự kiểm tra và quyết định áp dụng.
- **Bài 3 - Core Engine & Snort Rule Matching**: _(cập nhật dần)_

Khi mở Pull Request, GitHub Copilot đóng vai trò reviewer tự động - các comment của Copilot mang tính tham khảo, không tự động áp dụng thay đổi vào code.
