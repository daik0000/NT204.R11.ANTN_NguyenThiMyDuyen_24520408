# NT204.R11.ANTN_NguyenThiMyDuyen_24520408

Repo bài tập lớn môn **Hệ thống tìm kiếm, phát hiện và ngăn chặn xâm nhập**. Các bài tập được phát triển tiếp trên cùng repo, xây dựng dần một hệ thống **Intrusion Detection System (IDS)** bằng Python (Linux, Python 3.10+).

## Pipeline tổng quát

```
Capture (live / PCAP)
   -> Parser (IPv4, TCP/UDP, HTTP/DNS/SMTP)  -> IDSEvent chuẩn hóa
   -> Decoder          (giải mã percent-encoding, HTML entity, MIME)
   -> Preprocessor     (kiểm tra hợp lệ, chuẩn hóa, điền mặc định)
   -> Flow Tracker     (gom gói hai chiều theo flow, trạng thái TCP, thống kê)
   -> Rule Engine      (nạp rule 1 lần; mỗi gói: chọn rule ứng viên -> header -> flow -> flags/dsize -> content -> Detection Event)
   -> events.jsonl / flows.jsonl / detections.jsonl
```

Mỗi gói tin đi qua một pipeline duy nhất, dù lấy từ live traffic hay từ file PCAP. Một gói lỗi không làm dừng chương trình.

## Mục tiêu từng phần

**Part 1 — Packet Capture & Parser.** Thu thập lưu lượng từ network interface hoặc file PCAP, phân tích theo IPv4, TCP/UDP, HTTP/1.x, DNS, SMTP và chuyển mỗi gói thành một `IDSEvent` chuẩn hóa để các module phía sau không phải đụng tới raw packet. Ghi kết quả ra JSON Lines.

**Part 2 — Decoder, Preprocessor & Flow/Connection Tracker.** Giải mã dữ liệu mã hóa trong HTTP/SMTP mà vẫn giữ nguyên dữ liệu gốc; kiểm tra hợp lệ và chuẩn hóa event (đánh dấu `valid`/`partial`/`invalid`); gom các gói hai chiều thành flow, theo dõi trạng thái kết nối TCP, hết hạn flow theo timeout và xuất thống kê từng flow.

**Part 3 — Core Engine & Snort Rule Matching.** Xây dựng Core Engine cho IDS dựa trên signature/rule. Engine nhận dữ liệu chuẩn hóa từ Preprocessor và thông tin trạng thái/thống kê từ Flow/Connection Tracker, sau đó so khớp với bộ rule trong phạm vi được hỗ trợ để sinh Detection Event. Signature nằm hoàn toàn trong file `.rules`, không hard-code trong source code. Chi tiết phạm vi và định nghĩa ở mục "Part 3 — Core Engine" bên dưới.

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
| `--rules FILE` | (không) | File rule bổ sung, lặp được; được nạp sau `engine.rule_files`. File không tồn tại hoặc là thư mục: exit 1 |
| `--detections-output FILE` | `output/detections.jsonl` | Nơi ghi Detection Event (ghi nối tiếp); không tạo khi engine tắt |
| `--rules-report FILE` | `output/rules_report.jsonl` | Báo cáo mọi dòng rule với `status` và `reason`; được thay mới mỗi lần chạy, không tạo khi engine tắt |

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

## Part 3 — Core Engine: phạm vi và định nghĩa

### Cách engine làm việc

1. **Khởi động (một lần):** đọc các file trong `engine.rule_files` (rồi các file `--rules`) theo thứ tự -> tách từng dòng rule -> phân loại `valid` / `invalid` / `unsupported` (rule tắt bằng `disabled_sids` ghi là `disabled`) -> lưu rule hợp lệ theo đúng thứ tự trong file -> lập chỉ mục theo protocol và cổng đích. Mọi dòng rule, kể cả bị loại, được ghi vào `rules_report.jsonl` kèm lý do. Không có rule nào dùng được thì chương trình vẫn chạy như Part 2.
2. **Mỗi gói (sau Flow Tracker):** lấy rule ứng viên từ chỉ mục, rồi thử lần lượt từng rule theo thứ tự **rẻ -> đắt**: `header` -> `flow` -> `packet` (`flags`, `dsize`) -> `content`. Rule trượt ở stage nào thì dừng ở đó nên `content` chỉ được tìm khi mọi stage rẻ đã đạt. Mọi rule khớp đều sinh Detection (không dừng ở rule khớp đầu tiên), theo thứ tự rule trong file.
3. **Lỗi từng rule được cô lập:** một rule gây lỗi chỉ bị đếm vào `rule_errors` và cảnh báo (đầy đủ một lần cho mỗi `sid`); các rule khác vẫn được thử.

Cấu hình `engine` trong `config/settings.yaml`:

| Khoá | Mặc định | Ý nghĩa |
|---|---|---|
| `enabled` | `true` | `false`: engine không nạp rule, không ghi `detections.jsonl`/`rules_report.jsonl`; `events.jsonl` và `flows.jsonl` giống hệt Part 2 |
| `rule_files` | `[{path: config/rules/local.rules, enabled: true}]` | Danh sách file rule, đọc theo thứ tự; file lỗi hoặc không có chỉ cảnh báo |
| `disabled_sids` | `[]` | Tắt rule theo `sid` |
| `default_priority` | `3` | Priority khi rule không khai báo (số nguyên >= 1) |

### Phạm vi Snort được hỗ trợ

| Nhóm | Được hỗ trợ | Ngoài phạm vi (báo `unsupported`, không bỏ qua âm thầm) |
|---|---|---|
| Action | `alert` | `drop`, `reject`, `pass`, `log`, `sdrop`, `activate`, `dynamic` |
| Protocol | `tcp`, `udp`, `ip` (chữ thường) | `icmp`, `http`, `dns`, `smtp`, ... |
| Địa chỉ | `any`, IPv4 đơn, CIDR `a.b.c.d/n` (host bit được xoá) | biến `$VAR`, phủ định `!`, danh sách `[...]`, IPv6 |
| Cổng | `any`, `80`, `1:1024`, `:1023`, `5000:` | biến, `!80`, `[80,443]` |
| Chiều | `->`, `<>` | `<-` (không có trong Snort 2) |
| Nhận dạng | `msg`, `sid`, `rev`, `classtype`, `priority` | |
| Chỉ lưu, không ảnh hưởng khớp | `reference`, `metadata`, `gid` | |
| Nội dung | `content` (chuỗi, khối hex `\|47 45 54\|`, trộn cả hai) với `nocase`, `offset`, `depth`, `distance`, `within` | `content:!"..."`, `pcre`, `byte_test`, `byte_jump`, `http_uri`, `fast_pattern`, `isdataat`, ... |
| Flow | `to_server`, `to_client`, `from_client`, `from_server`, `established`, `not_established` | `stateless`, `only_stream`, `no_stream`, `no_frag`, ... |
| Gói TCP | `flags` (`FSRPAUCE`, `0`, với `!` `+` `*`), `dsize` (`N`, `<N`, `>N`, `N<>M`) | `flags` có mặt nạ (`SA,12`), `flowbits`, `threshold`, `ack`, `seq`, `ttl`, ... |

Keyword nằm ngoài ba tập hằng `IDENTIFICATION_KEYWORDS`, `PASSIVE_KEYWORDS`, `MATCH_KEYWORDS` (trong `src/rules/parser.py`) luôn là `unsupported`, vì bỏ qua chúng sẽ làm rule khớp rộng hơn ý của tác giả (ví dụ bỏ `pcre` hay `flowbits`).

### Các quyết định thiết kế

- **Signature chỉ nằm trong file `.rules`.** Không có chuỗi tấn công nào trong mã Python; `config/rules/local.rules` chỉ là rule mẫu để chạy thử.
- **`invalid` thắng `unsupported`.** Thứ tự phân loại một dòng: cấu trúc, header, option được hỗ trợ (giá trị và liên-option), cuối cùng là keyword ngoài phạm vi. Nếu có cả hai loại thì báo `invalid`; nhiều `unsupported` thì header đứng trước option.
- **Rule trùng `sid`:** rule đầu tiên thắng, các rule sau (kể cả ở file khác) là `invalid:duplicate_sid`. Rule `invalid`/`unsupported` không chiếm `sid`.
- **Thứ tự kết quả theo thứ tự rule trong file** (không theo `sid`), và mọi rule khớp đều được báo.
- **Chỉ mục là bộ lọc thô** theo protocol và cổng đích: rule `->` đăng ký theo cổng đích, rule `<>` đăng ký ở cả cổng nguồn lẫn cổng đích của rule (để không bỏ sót gói đi chiều ngược). Rule chỉ mục loại thì chắc chắn không khớp; rule qua được vẫn phải qua các stage.
- **`<>`:** thử chiều thuận hoặc chiều đảo; chiều đảo so cả cặp (IP, cổng) cùng lúc, không trộn.
- **`nocase` chỉ đổi A-Z (ASCII)**, như Snort; ký tự ngoài ASCII trong rule được mã hoá UTF-8 (giống byte trong file rule). Byte thô viết bằng khối hex.
- **Event vẫn được đánh giá** khi `status` là `IGNORED` (`unknown_policy: skip`) hoặc giao thức ứng dụng `UNKNOWN`. Engine bỏ qua và đếm `events_skipped` khi: engine tắt, không có rule, `processing_action` là `skipped`/`dropped`, `preprocess_status` là `invalid`, hoặc không có TCP/UDP và cổng đích.
- **Engine không sửa field nào của event.** Phần duy nhất được thêm vào code Part 2 là `FlowTracker.snapshot()` (chỉ đọc).

### Detection Event (`detections.jsonl`, mỗi dòng một Detection)

| Field | Ý nghĩa |
|---|---|
| `sid`, `rev`, `msg`, `classtype` | Lấy từ rule (`classtype` là `null` nếu rule không có) |
| `priority` | Priority của rule, hoặc `engine.default_priority` |
| `timestamp`, `packet_id` | Của event; `packet_id` dùng để tra ngược về `events.jsonl` |
| `src_ip`, `src_port`, `dst_ip`, `dst_port` | 5-tuple của gói (theo chiều gói, không theo chiều flow) |
| `protocol` | `TCP` hoặc `UDP` |
| `application_protocol` | `app_protocol` của event (có thể `null` hoặc `UNKNOWN`) |
| `flow_id` | Flow của gói, để tra về `flows.jsonl` |
| `flow_direction` | `to_server` / `to_client` (vai trò của bên gửi) hoặc `null`; **không phải** `forward`/`backward` |
| `matched` | Luôn là danh sách không rỗng: với mỗi `content` có `{"keyword": "content", "value": <chuỗi trong rule>, "offset": <vị trí trong payload>, "length": <số byte>}`; rule không có `content` thì `[{"keyword": "header"}]` |

### `to_server`, `to_client`, `established`

- **Client/server của flow:** TCP có SYN đầu tiên thì bên gửi SYN là client. Ngược lại (TCP bắt giữa chừng, UDP): nếu đúng một cổng nằm trong `ports` thì đó là server; không thì cổng nhỏ hơn là server; hai cổng bằng nhau thì `endpoint_a` là client.
- **`to_server` / `to_client`** là vai trò của bên gửi **gói hiện tại**. `forward` chỉ có nghĩa "do `endpoint_a` gửi", và `endpoint_a` là server nếu gói đầu bắt được là phản hồi.
- **`established`** tính theo trạng thái **sau** gói hiện tại: TCP là `ESTABLISHED`, `CLOSING` hoặc `CLOSED` (gói ACK hoàn tất bắt tay đã tính); `HANDSHAKE` và `RESET` là `not_established`. UDP là đã thấy ít nhất một gói chiều ngược lại, kể cả gói hiện tại.
- Gói không có flow (chưa theo dõi, hoặc flow đã bị xuất): mọi rule có `flow:` coi như không khớp, rule không có `flow:` không bị ảnh hưởng.

### `offset`, `depth`, `distance`, `within`

- `offset:N` và `depth:N` (tuyệt đối): cửa sổ tìm là `[offset, offset + depth)`; `depth` là **kích thước** cửa sổ, không phải vị trí. Không có `depth` thì tìm đến hết payload. Pattern phải nằm trọn trong cửa sổ.
- `distance:N` và `within:N` (tương đối, tính từ **cuối** lần khớp của content liền trước): cửa sổ là `[prev_end + distance, prev_end + distance + within)`; `distance` có thể âm (cửa sổ kẹp về 0); content đầu tiên của rule coi `prev_end = 0`.
- Nhiều `content` được khớp **có quay lui**: nếu content sau không khớp thì thử lần xuất hiện kế tiếp của content trước, và rule chỉ trượt khi không còn cách nào cho cả chuỗi khớp. Vị trí báo trong `matched` là của tổ hợp thành công.
- Một content không được vừa có `offset`/`depth` vừa có `distance`/`within` (`invalid:mixed_absolute_relative`); `depth` hoặc `within` nhỏ hơn độ dài pattern là `invalid`.

### `rules_report.jsonl` và mã `reason`

Mỗi dòng: `file`, `line`, `status`, `reason`, `sid`, `text`. `status` là `valid` (`reason` là `null`), `invalid`, `unsupported` hoặc `disabled` (rule hợp lệ bị tắt bằng `disabled_sids`, `reason` là `disabled:sid`).

| Mã | Ý nghĩa |
|---|---|
| `invalid:malformed_rule` | Không tách được header và option (thiếu `(` hoặc `)`, chữ thừa sau `)`, chuỗi chưa đóng ngoặc kép) |
| `invalid:bad_header`, `invalid:bad_ip`, `invalid:bad_port`, `invalid:bad_direction` | Header sai số phần/từ khoá, IP, cổng hoặc chiều sai |
| `invalid:missing_sid`, `invalid:bad_sid`, `invalid:duplicate_sid`, `invalid:missing_msg` | Thiếu hoặc sai `sid`/`msg`, `sid` trùng |
| `invalid:bad_option_value:<k>` | Giá trị của option `<k>` không dùng được |
| `invalid:duplicate_option:<k>` | Option `<k>` xuất hiện hai lần |
| `invalid:modifier_without_content` | `nocase`/`offset`/... khi chưa có `content` trước đó |
| `invalid:depth_lt_pattern`, `invalid:within_lt_pattern` | `depth`/`within` nhỏ hơn độ dài pattern |
| `invalid:mixed_absolute_relative` | Một content vừa tuyệt đối vừa tương đối |
| `invalid:flags_requires_tcp` | `flags` trong rule `udp` |
| `invalid:conflicting_flow` | `flow` mâu thuẫn (`to_server,to_client`, `established,not_established`) |
| `invalid:internal_error` | Lỗi bất ngờ khi phân tích dòng đó |
| `unsupported:action:<x>`, `unsupported:protocol:<x>` | Action hoặc protocol ngoài phạm vi |
| `unsupported:ip_syntax`, `unsupported:port_syntax` | Biến, phủ định hoặc danh sách trong IP/cổng |
| `unsupported:keyword:<k>` | Keyword ngoài phạm vi (`pcre`, ...) |
| `unsupported:flow_option:<x>`, `unsupported:flags_mask`, `unsupported:content_negation` | Giá trị `flow` ngoài phạm vi, `flags` có mặt nạ, `content:!"..."` |
| `disabled:sid` | `sid` nằm trong `engine.disabled_sids` |

### Chạy và kiểm thử

```bash
python main.py --pcap input.pcap --rules my.rules \
    --detections-output out/detections.jsonl --rules-report out/rules_report.jsonl
pytest TEST/BT3
```

Dòng tóm tắt cuối giữ nguyên các trường của Part 2 và thêm `rules(loaded=…, invalid=…, unsupported=…)`, `events_evaluated`, `candidates`, `detections`.

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
- Engine vẫn đánh giá event có `status` `IGNORED` (chính sách `unknown_policy: skip` chỉ quyết định việc ghi log) và event có giao thức ứng dụng `UNKNOWN`, vì header transport và payload vẫn nguyên vẹn. Engine chỉ bỏ qua (và đếm `events_skipped`) event khi engine tắt, không có rule, `processing_action` là `skipped`/`dropped`, `preprocess_status` là `invalid` hoặc không có TCP/UDP và cổng đích; bộ đếm này chỉ do engine tính.
- So khớp nhiều `content` có quan hệ tương đối dùng quay lui có ghi nhớ trạng thái đã thất bại, nên chi phí là đa thức (không bùng nổ theo số lần xuất hiện); do không ghép luồng TCP nên mỗi gói tối đa khoảng 1460 byte. Số `content` của một rule bị giới hạn bởi độ sâu đệ quy (khoảng 900), còn rule thật chỉ có vài `content`.
- `--rules` trỏ cùng một đường dẫn hai lần, hoặc trùng với file trong `engine.rule_files`, thì chỉ được nạp một lần và báo cáo không có dòng lặp. Cùng `sid` nhưng ở file khác thì rule đến sau bị báo `invalid:duplicate_sid`. Khi engine tắt, `--rules` vẫn được kiểm tra đường dẫn (sai thì exit 1) rồi bị bỏ qua kèm cảnh báo `--rules ignored because the engine is disabled`.
- Khi engine tắt (hoặc cấu hình không có section `engine`), `rules_report.jsonl` không được tạo cũng không bị xoá: file cũ còn trong thư mục output (nếu có) không phản ánh lần chạy hiện tại. Detection của một gói được ghi trước dòng event tương ứng trong `events.jsonl`; hai file độc lập, `packet_id` là khoá để tra ngược.
- Indexer chỉ lọc thô theo protocol và cổng đích; dải cổng được duyệt tuyến tính (hướng cải tiến: interval tree). Event không có cổng (ICMP, ARP, thiếu tầng transport) không có rule ứng viên.
- `dsize` đo payload của từng segment/datagram, không ghép lại luồng TCP (giống Snort). Gói TCP tới cổng 80 mang payload không phải HTTP bị Part 1 đánh `MALFORMED`, nên không tới được engine.
- `match_header` đổi IP của gói sang số nguyên mỗi lần thử một rule ứng viên, chưa phải một lần cho cả gói. Event có IP không hợp lệ không khớp rule nào, kể cả `any any`.
- Không ghép lại luồng TCP: `content` và `dsize` chỉ nhìn payload thô của từng gói, nên một chuỗi bị chia qua hai segment sẽ không khớp.
- Gói `RST` đến sau khi kết nối đã established có state `RESET` nên bị coi là `not_established` (Snort giữ `established`).
- Vai trò `to_server`/`to_client` của flow TCP không bắt đầu bằng SYN (và của flow UDP) được suy ra từ cổng, nên có thể sai khi cả hai cổng đều là cổng tạm. Khi flow đã bị xuất khỏi bảng, engine không đoán: mọi rule có `flow:` coi như không khớp.

## AI usage disclosure

Trong quá trình phát triển, Claude Sonnet 5.5 (Anthropic) được sử dụng như sau:

- **Bài 1 - Packet Capture**: vai trò **review code và đưa ra gợi ý chỉnh sửa** cho từng commit trước khi đưa lên repo - không viết thay toàn bộ code. Phần lớn code nộp bài do người thực hiện tự viết; Claude chỉ đọc lại, chỉ ra lỗi/rủi ro tiềm ẩn (ví dụ: sai lệch so với schema đã chốt, race condition, dữ liệu bị parse sai âm thầm) và đề xuất hướng sửa, việc quyết định áp dụng sửa nào do người thực hiện tự cân nhắc.
- **Bài 2 - Decoder, Preprocessor và Flow Tracker**: lập kế hoạch Issue/commit (timeline) cho Bài 2; review từng commit như ở Bài 1; với một số file, Claude đề xuất đoạn mã sửa kèm unit test để người thực hiện đối chiếu, tự kiểm tra và quyết định áp dụng.
- **Bài 3 - Core Engine & Snort Rule Matching**: Claude Sonnet 5.5 được dùng để **viết code và unit test** cho từng commit theo Issue do người thực hiện đưa ra, gồm: các schema `Rule`, `ParseResult`/`RuleRecord`/`LoadReport`, `Detection`, `FlowContext`/`MatchResult` (`src/models/`); đọc và phân tích rule, kho lưu rule và chỉ mục (`src/rules/`: `loader.py`, `parser.py`, `validator.py`, `repository.py`, `indexer.py`, `report.py`); các matcher header/flow/flags/dsize/content, engine đánh giá, thống kê, Detection generator và lớp `Engine` (`src/engine/`); phần cấu hình `engine` (`src/utils/config.py`); tích hợp vào `Pipeline`. Mỗi commit đều được đọc lại và review (nhận xét review được đưa ngược lại vào code); việc quyết định áp dụng thay đổi nào là người thực hiện tự cân nhắc.

Khi mở Pull Request, GitHub Copilot đóng vai trò reviewer tự động - các comment của Copilot mang tính tham khảo, không tự động áp dụng thay đổi vào code.
