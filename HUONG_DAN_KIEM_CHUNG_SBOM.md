# Kiểm chứng SBOM trước bàn giao

## Prompt triển khai

Xây dựng cho nhà phát triển một luồng trả lời hai câu hỏi trước khi bàn giao phần mềm. Một là mỗi thông tin nguồn gốc trong SBOM lấy từ đâu và checksum đã được đối chiếu trên tệp nào. Hai là phiên chạy của bản build đã quan sát những thư viện nào trên trình duyệt và trên backend, gồm cả gói có trong SBOM tĩnh và gói phát sinh ngoài danh mục. Áp dụng trước cho dự án JavaScript/TypeScript chạy Node.js, Express hoặc Next.js. KickZone là ca hồi quy cho log lịch sử bị trộn dữ liệu từ hai dự án.

1. Giữ bản SBOM tĩnh gốc. Băm đúng các byte nhập vào, tra bản phát hành theo PURL và phiên bản, lưu nguồn tham chiếu. Tách kết quả tra kho, kết quả so tệp và bằng chứng phả hệ. Hiển thị rõ trường hợp thiếu phiên bản, kho trả 404, lỗi kết nối, thiếu checksum và hệ sinh thái chưa hỗ trợ.
2. Thu tài nguyên trình duyệt bằng CDP và module máy chủ từ chính tiến trình chạy ứng dụng. Chứng minh hai phía liên quan bằng cùng mã request và kiểm tra fingerprint của SBOM tĩnh trước khi ghép. Ghi lại thao tác, commit hoặc mã bản build và giới hạn quan sát của phiên.
3. Trong báo cáo, cho phép truy ngược từ gói và phiên bản đến bằng chứng. Phân loại `MATCHED`, `RUNTIME_ONLY`, `STATIC_ONLY`, `UNRESOLVED`. Chỉ xác nhận “ngoài danh mục” trong phạm vi bản SBOM đã chọn. Một gói có cùng tên nhưng lệch phiên bản cần được giải thích riêng.
4. Nghiệm thu bằng một ca khớp, một ca chỉ có ở runtime, một ca còn mơ hồ và một lần ghép sai dự án bị từ chối. Lặp lại trên ứng dụng độc lập. Sau khi kiểm chứng đối sánh mới đánh giá embedding đồ thị.

## Căn cứ để trình bày với giảng viên

| Căn cứ | Phạm vi áp dụng trong đồ án |
| --- | --- |
| CycloneDX quy định cấu trúc component, hashes, properties và phả hệ. | Dùng đúng schema theo specVersion. Chỉ giữ pedigree có căn cứ từ đầu vào. Một commit do registry công bố được ghi nguồn trong properties. Bản làm giàu dùng checksum hex, giữ các trường truy vết dưới properties. [CycloneDX 1.6](https://cyclonedx.org/docs/1.6/json/) |
| NIST định nghĩa thuật toán SHA-256. | Băm toàn bộ byte của tệp SBOM ban đầu. So digest với giá trị tham chiếu nhận từ bên bàn giao qua kênh tin cậy. Hai giá trị bằng nhau là bằng chứng về nội dung. Xác minh người ký hoặc danh tính nhà phát hành cần chữ ký và khóa tin cậy riêng. [NIST FIPS 180-4](https://csrc.nist.gov/pubs/fips/180-4/upd1/final) |
| Torres-Arias và cộng sự mô tả xác thực các bước trong chuỗi cung ứng bằng in-toto. | Dùng làm cơ sở nghiên cứu để gắn từng tuyên bố với vật phẩm, chủ thể và bằng chứng. Phần đã triển khai thực hiện tra metadata và đối chiếu checksum. Xác minh attestation có chữ ký của builder là phạm vi nghiên cứu tiếp theo. [USENIX Security 2019](https://www.usenix.org/conference/usenixsecurity19/presentation/torres-arias) |
| npm dùng SRI cho tarball. Maven công bố checksum theo tọa độ và tệp phát hành. | Băm byte của đúng tarball hoặc JAR bằng thuật toán kho công bố. Giải mã SRI base64 thành hex khi xuất CycloneDX. Ghi riêng SHA-256 của tệp đã kiểm tra. [npm](https://docs.npmjs.com/cli/v11/configuring-npm/package-lock-json/) · [Maven](https://maven.apache.org/repository/layout.html) |

## Kiểm tra nguồn gốc

Trang Provenance lưu byte của SBOM gốc trong trình duyệt cùng SHA-256. Khi tải bản chuẩn hóa tương ứng lên trang Reconciliation, nhấn **Tải lại SBOM gốc** để nhận đúng tệp đầu vào. Với các bản đã lưu từ phiên bản cũ, nạp lại tệp gốc để bổ sung bản sao.

Trên trang **Provenance**, nạp SBOM gốc và lưu bản làm giàu. Có thể nhập SHA-256 tham chiếu độc lập để kiểm tra SBOM. Mở chi tiết gói có checksum, chọn đúng tarball hoặc JAR đang bàn giao. Giao diện băm tệp tại máy và xuất biên bản JSON chứa URL tra cứu, thuật toán, giá trị công bố, giá trị tính lại, SHA-256 và thời điểm. Với npm, chọn tarball nguyên bản trước khi giải nén. Thử cả tệp đúng và bản sao đổi một byte. Khi một gói riêng không xuất hiện ở kho công cộng, đối chiếu thêm đường dẫn manifest/workspace hoặc kho riêng của nhà phát triển.

## Thu một phiên frontend và backend

1. Chọn cùng bản build để lập SBOM và chạy ứng dụng. Dùng terminal mới ở thư mục dự án đích hoặc workspace backend nơi lệnh dev vẫn thường chạy. Truyền **SBOM gốc** cho agent và tải lên **bản chuẩn hóa từ chính SBOM ấy** trong công cụ. Agent ghi SHA-256 của tệp được người vận hành chọn. Để kiểm chứng bản deploy, lưu thêm commit/build ID từ hệ thống phát hành.
2. Chạy lệnh dưới đây trong PowerShell. Thay hai đường dẫn bằng vị trí thực. Với pnpm thay giá trị Manager thành pnpm. Dùng Script start khi cần đánh giá bản build sản xuất. Terminal in thư mục chứa các file backend. Với ứng dụng có frontend và API độc lập, bật agent trên tiến trình API. Với Next.js full stack, bật trên lệnh chạy Next.

```powershell
& 'C:\duong-dan\cong-cu\scripts\nodejs-runtime-collector\start-capture.ps1' -StaticSbom 'C:\du-an\sbom.json' -Manager npm -Script dev
```

Trên Linux/macOS, đặt SBOM_STATIC_FILE và SBOM_EVIDENCE_DIR thành đường dẫn tuyệt đối. Thêm `--require "/đường/dẫn/session-agent.cjs"` vào NODE_OPTIONS của lệnh npm hoặc pnpm. Node truyền preload xuống tiến trình con thừa kế môi trường. CommonJS dùng sự kiện nạp thành công qua require. Native ESM dùng load hook khi Node cung cấp registerHooks, ví dụ Node 24. TypeScript được quan sát qua module đầu ra hoặc loader mà ứng dụng sử dụng. [Node.js module hooks](https://nodejs.org/api/module.html#moduleregisterhooksoptions)

3. Mở trang **Reconciliation**, tải SBOM chuẩn hóa, nhập URL và nhấn **Run** để ghi lượt tải trang. Với một thao tác tương tác như đăng nhập, chạy lệnh sau từ repo công cụ ở terminal thứ hai. Trong cửa sổ Chrome vừa mở, thực hiện thao tác trong 60 giây rồi nhập tệp qua **Tải log → Chọn log**. Đặt `SBOM_SCENARIO` thành tên thao tác, `SBOM_BUILD_ID` thành mã build frontend đang đo nếu biết. Wrapper backend nhận `-BuildId` hoặc lấy commit Git của thư mục chạy. Báo cáo JSON lưu cả thông tin phiên và các request dùng để ghép.

```powershell
$env:SBOM_SCENARIO = 'Đăng nhập tài khoản thử'
node scripts/runtime-collector/cdp-scanner.js http://localhost:3000 browser.json --interactive
```

4. Chọn **Terminal backend → Bổ sung log backend rời** và nhập file `backend-*.json` của tiến trình xử lý request. Có thể chọn nhiều file của nhiều worker có tham gia. CDP lấy mã ngẫu nhiên từ response header `x-sbom-request-id`. Công cụ đối chiếu với mã của request hoàn thành trong log backend, kiểm tra SHA-256 của SBOM gốc và chỉ lấy gói nạp tới thời điểm kết thúc request chung cuối cùng. Một HTTP response từ đúng backend cần đến được trình duyệt. Proxy phải giữ header nếu chuyển tiếp response. Với tác vụ nền chạy sau response, thực hiện thêm một request tới backend sau khi tác vụ hoàn tất. Khi chạy lại một kịch bản, khởi động tiến trình mới để tránh module lưu trong cache từ phiên trước.
5. Nhấn đối sánh, lọc RUNTIME_ONLY để rà soát gói ngoài danh mục. Xuất log runtime JSON giữ cả bằng chứng backend đã ghép. Xuất báo cáo JSON hoặc CSV để bàn giao. RUNTIME_ONLY có thể xuất hiện do phạm vi SBOM, CDN, plugin hoặc công cụ dev. Kiểm tra lại trên bản build sản xuất trước khi kết luận về phần mềm giao khách hàng.

## Cách đọc giới hạn quan sát

- Module đã nạp trong tiến trình có thể phục vụ khởi động, biên dịch dev hoặc request khác. Bằng chứng gắn với tiến trình và khoảng thời gian. Nó không khẳng định mọi module đều được gọi bởi thao tác đăng nhập.
- Bundle hoặc source map có thể chứa nhiều thư viện. Fingerprint trong bundle chỉ là dấu hiệu nhận diện. Phiên bản phải có căn cứ riêng. Hash của một script được giữ cùng quan sát script. Thống kê heap là của cả tiến trình.
- Hai phiên bản cùng tên được giữ riêng. Một gói tĩnh có thể xuất hiện ở nhiều lockfile. Đếm bản ghi tĩnh, định danh gói và số quan sát theo từng nguồn khi giải thích số liệu.
- Một URL deploy chỉ cho phép quan sát bên trình duyệt. Muốn kiểm chứng backend cần chạy agent bên máy chủ hoặc trên bản build tương ứng mà nhà phát triển kiểm soát. Mã được đóng gói vào một server bundle có thể mất ranh giới module. Với tiến trình ESM loader hook chỉ chứng minh loader đã nạp module. Những phần chưa quan sát cần được ghi trong biên bản.
- Với ba tệp KickZone lịch sử, nguồn trình duyệt có 5 tên. Hai giá trị phiên bản React từ fingerprint cần để chưa rõ. Phần server cũ có PID 5716 của sample-app và thiếu mã request, nên chỉ nhập phần trình duyệt. Ghi nhận xlsx là thư viện ngoài của KickZone đòi hỏi bằng chứng khác từ đúng backend.

## Kết quả kiểm tra của lần triển khai

| Ca kiểm tra | Kết quả quan sát |
| --- | --- |
| Tarball công khai is-number@7.0.0 | Java tra đúng phiên bản npm. SHA-512 tính trên byte tarball khớp checksum công bố. SHA-256 của cùng tarball là `7b75c1057198cf97696909a9bee176c9c5e9bcb5b03bf3ecef2f484defadd51e`. Bài kiểm thử giao diện phát hiện khi đổi một byte của tệp thử. |
| Phát lại log KickZone | 871 bản ghi tĩnh và 5 tên frontend. Báo cáo trả 0 MATCHED, 0 RUNTIME_ONLY, 863 STATIC_ONLY và 11 dòng UNRESOLVED. Một tên runtime có thể ứng với nhiều bản ghi tĩnh. Cần phiên backend KickZone mới để đánh giá toàn ứng dụng. |
| Đối chiếu schema CycloneDX 1.6 của KickZone | Bản gốc có 98 lỗi schema, bản làm giàu cũ có 2.703 lỗi. Đầu ra chạy lại từ bản gốc trong phép thử ngoại tuyến có 0 lỗi theo cùng bộ kiểm tra. Phép thử này thay bộ tra registry bằng kết quả ngoại tuyến để đo riêng cấu trúc và bảo toàn dữ liệu. |
| Ứng dụng Node độc lập | Chrome headless nhận response từ server thật và ghép được module CommonJS, ESM. Các ca sai SHA-256 hoặc thiếu request chung bị từ chối. Chạy riêng wrapper với npm và pnpm đều tạo được log từ server. |

Trong khung **Terminal backend**, Chrome và Edge hỗ trợ chọn file log đang ghi và cập nhật các lần nạp module cùng HTTP request. Bấm **Ghép bản ghi này vào phiên** để kiểm tra SHA-256 và request trước khi đối sánh. Có thể nhập trực tiếp log đã xuất thay cho thu URL mới.

Nếu log runtime xuất ra đã có backendEvidence của phiên, Nguồn 2 chỉ cần một file. Chọn **Thu từ URL** để thu một phiên trình duyệt mới.
