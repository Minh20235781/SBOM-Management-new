# Nền Tảng Phân Tích Rủi Ro và Quản Lý SBOM Trong Quy Trình DevOps (GR2)

> **Đồ Án Tốt Nghiệp 2 (GR2)**: *Xây dựng website quản lý thông tin của các hệ thống theo quy trình DevOps dựa trên SBOM - Nguồn gốc và chính sách*<br/>
> **Sinh viên thực hiện**: Nguyễn Nhật Minh (MSSV: 20235781)<br/>
> **Giảng viên hướng dẫn**: TS. Vũ Thị Hương Giang<br/>
> **Đơn vị đào tạo**: Trường Công nghệ Thông tin & Truyền thông - Đại học Bách khoa Hà Nội (HUST)

---

## 1. Giới Thiệu Tổng Quan

Trong quy trình phát triển và vận hành phần mềm hiện đại (DevSecOps), danh mục thành phần phần mềm (Software Bill of Materials - SBOM) đóng vai trò cốt lõi trong việc quản lý chuỗi cung ứng phần mềm. Tuy nhiên, các giải pháp SBOM truyền thống hiện nay đang đối mặt với hai thách thức lớn:
1. **Thiếu thông tin nguồn gốc và tính toàn vẹn (Static Provenance Gap)**: Các file SBOM trích xuất từ file manifest (như `package.json`, `pom.xml`) thường thiếu thông tin phả hệ nguồn gốc (`pedigree`), dễ bị tấn công hoán đổi tên gói (typosquatting) hoặc giả mạo phiên bản.
2. **Điểm mù giữa khai báo tĩnh và vận hành thực tế (Runtime Blind Spot)**: Các file manifest chứa hàng trăm thư viện dư thừa hoặc chỉ phục vụ kiểm thử (dev dependencies), trong khi các thư viện nạp ngầm, phụ thuộc cấp hai nạp qua mạng (CDN) hoặc sinh ra trong bộ nhớ lại không hề có trong file manifest tĩnh.

Hệ thống **SBOM Risk Analysis Platform (Phiên bản GR2)** giải quyết trọn vẹn hai bài toán trên thông qua hai trục công nghệ chủ đạo:
* **Nguồn gốc và chuẩn hóa SBOM tĩnh.** Tra cứu bản phát hành npm hoặc Maven Central theo định danh, ghi nguồn tham chiếu và so byte của tệp phát hành với checksum công bố.
* **Đối sánh runtime.** Thu dữ liệu bằng Chromium CDP và preload trong tiến trình Node.js. Đối chiếu request và SHA-256 của SBOM gốc trước khi ghép hai nguồn.

---

## 2. Kiến Trúc Hệ Thống Đa Tầng

```
┌──────────────────────────────────────────────────────────────────────────────────┐
│                             GIAO DIỆN NGƯỜI DÙNG                                 │
│                   React 18 + Vite (http://localhost:5173)                        │
│   - Dashboard & Thống kê rủi ro               - Bảng SBOM & Phả hệ Pedigree      │
│   - SBOM Provenance: Chuẩn hóa nguồn gốc      - Runtime Reconcile: Đối soát đa nguồn │
│   - F12 Network & Memory Inspector            - Đồ thị phụ thuộc Graph & GNN     │
└────────────────────────────────────────┬─────────────────────────────────────────┘
                                         │ HTTP REST / SSE (Port 8080)
┌────────────────────────────────────────▼─────────────────────────────────────────┐
│                           BACKEND SERVER (SPRING BOOT)                            │
│                        Java 21 + Hibernate + PostgreSQL / H2                     │
│                                                                                  │
│  [Module 1: SbomProvenanceService]        [Module 2: RuntimeReconciliationService]│
│  - Validate & Normalize PURL              - Chromium CDP Instrumentation Runner  │
│  - npm Registry / Maven Central API       - Node.js Server Module Hook Collector │
│  - SHA-256 FIPS-180-4 Engine              - Realtime F12 SSE Stream Emitter      │
│  - CycloneDX Pedigree Builder             - 4-State Reconciliation Match Engine  │
│                                                                                  │
│  [Module 3: SbomValidationService]        [Module 4: AI & Graph Analytics]       │
│  - Consistency & Weighted Voting          - Graph Builder & Anomaly Detection    │
└───────────────────┬───────────────────────────────────┬──────────────────────────┘
                    │                                   │
      gRPC / HTTP   ▼                     gRPC / HTTP   ▼
┌───────────────────────────────┐       ┌───────────────────────────────┐
│     GNN SERVICE (PORT 8000)   │       │     RF SERVICE (PORT 8002)    │
│  Python 3.11 + FastAPI + PyG  │       │ Python 3.11 + FastAPI + Scikit│
│  Lan truyền rủi ro đồ thị     │       │ Dự đoán mức độ rủi ro         │
└───────────────────────────────┘       └───────────────────────────────┘
```

---

## 3. Các Tính Năng Cốt Lõi Trong GR2

### 3.1. Nguồn gốc và checksum

Trang Provenance tra cứu bản phát hành theo PURL, ghi checksum tham chiếu và cho phép chọn tệp tarball hoặc JAR để đối chiếu. SHA-256 của SBOM được tính trên byte đầu vào. Cấu trúc pedigree có sẵn được giữ theo nguồn. [Căn cứ nghiên cứu và hướng dẫn kiểm chứng](HUONG_DAN_KIEM_CHUNG_SBOM.md)

### 3.2. Thu thập dữ liệu Runtime đa tầng
* **Tầng Client & Mạng (Browser)**: Sử dụng Chromium CDP (`cdp-scanner.js`) tự động khởi chạy trình duyệt không đầu (headless browser), kích hoạt Performance Ledger, chụp nhật ký mạng và nạp tài nguyên.
* **Tầng máy chủ Node.js** dùng preload qua NODE_OPTIONS, ghi module theo tiến trình và nối log với CDP bằng mã request và SHA-256 của SBOM tĩnh.
* **F12 Network & Memory Inspector thời gian thực**: Giao diện F12 tích hợp trực tiếp trên web hỗ trợ xem tiến trình tải Waterfall, dung lượng, thời gian đáp ứng và bóc tách gói phụ thuộc theo thời gian thực qua Server-Sent Events (SSE).

### 3.3. Bộ máy đối soát đa nguồn tự động (`/reconciliation`)
* Cổng kiểm soát Nguồn 1 chỉ tiếp nhận các tệp SBOM tĩnh **đã qua chuẩn hóa và xác thực nguồn gốc**.
* Đối chiếu ma trận 2 chiều giữa thành phần khai báo tĩnh và dữ liệu vận hành runtime, tự động phân loại thành 4 nhóm bản ghi:
  * **MATCHED** gồm các bản ghi có định danh gói và phiên bản khớp.
  * **STATIC ONLY** gồm các bản ghi tĩnh chưa quan sát trong phiên đã chọn.
  * **RUNTIME ONLY** gồm các gói quan sát được nhưng chưa có định danh tương ứng trong SBOM tĩnh.
  * **UNRESOLVED** gồm thiếu phiên bản, chênh lệch phiên bản hoặc các trường hợp cần thêm bằng chứng.

---

## 4. Bảng Số Liệu Thực Nghiệm Trên 3 Dự Án Thực Tế

Hệ thống đã được kiểm chứng đối soát trên 3 dự án thực tế đại diện cho các hệ sinh thái và quy mô khác nhau:

| Dự Án | Hệ Sinh Thái | Nguồn Tĩnh | Nguồn Runtime | MATCHED | STATIC ONLY | RUNTIME ONLY | UNRESOLVED | Ý Nghĩa An Toàn Thông Tin |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: | :--- |
| **KickZone** | JavaScript, Node.js | 871 | 5 frontend | 0 | 863 | 0 | 11 | Phát lại log lịch sử. Số liệu là số dòng đối sánh. Cả 5 nhận diện frontend đều chưa xác nhận phiên bản. Log server cũ đến từ ứng dụng mẫu. |
| **Taxi-Booking-Web-App** | React, Node.js | 355 | 26 | 16 | 336 | 10 | 3 | Bóc tách 10 thư viện nạp ngầm ngoài manifest, xác định đúng 16 thư viện thực thi |
| **IoT ThingsBoard** | Java, Maven đa module | 2.281 | 25 | 42 | 2.229 | 4 | 10 | Giảm trừ 2.229 cảnh báo sai cho hệ thống IoT lớn, phát hiện 10 vị trí xung đột |

---

## 5. Cấu Trúc Thư Mục Dự Án

```
GR_PROJECT-main/
├── demo/                                # Backend Spring Boot (Java 21)
│   ├── src/main/java/com/example/sbom/
│   │   ├── provenance/                  # Module xác thực nguồn gốc & chuẩn hóa pedigree
│   │   ├── service/reconciliation/      # Module đối soát đa nguồn & runtime reconciliation
│   │   ├── controller/                  # Các REST Controller (Provenance, Reconcile, Scan,...)
│   │   ├── service/validation/          # Bộ quy tắc đánh giá tính nhất quán và điểm tin cậy
│   │   └── entity/                      # Entity CSDL PostgreSQL / JPA
│   ├── pom.xml
│   └── mvnw.cmd
├── sbom-frontend/                       # Frontend Dashboard (React + Vite)
│   ├── src/
│   │   ├── pages/Provenance/            # Trang xác thực nguồn gốc & chuẩn hóa SBOM tĩnh
│   │   ├── pages/Reconciliation/        # Trang đối soát đa nguồn Static vs Runtime
│   │   ├── components/reconciliation/   # F12 Network & Memory Inspector thời gian thực
│   │   ├── api/                         # provenanceApi.js, reconciliationApi.js,...
│   │   └── App.jsx
│   ├── package.json
│   └── vite.config.js
├── scripts/
│   ├── nodejs-runtime-collector/        # Agent hook Module._load cho máy chủ Node.js
│   │   └── nodejs-agent.js
│   └── runtime-collector/               # Bộ quét Chromium CDP thu thập lưu lượng mạng & RAM
│       ├── cdp-scanner.js
│       └── package.json
├── chrome-extension/                    # Tiện ích mở rộng Chrome DevTools kết nối Live F12
│   ├── devtools.js
│   ├── manifest.json
│   └── panel.js
├── test-apps/sample-app/                # Ứng dụng mẫu phục vụ kịch bản kiểm thử runtime
│   ├── server.js
│   ├── sbom-static.json
│   └── package.json
├── gnn-training/                        # Dịch vụ học máy phân tích rủi ro đồ thị phụ thuộc
├── ml-zenodo-a/                         # Mô hình Random Forest suy luận rủi ro
└── README.md
```

---

## 6. Hướng Dẫn Cài Đặt & Chạy Hệ Thống

### 6.1. Yêu cầu môi trường
* **Node.js**: Phiên bản 22.12 trở lên cho frontend và bộ thu thập Chromium
* **Java Development Kit (JDK)**: JDK 21 (hoặc JDK 17)
* **Python**: Phiên bản 3.10 - 3.12 (phục vụ các service AI/ML nếu cần)

### 6.2. Khởi động Backend (Spring Boot - Port 8080)

Mở PowerShell tại thư mục dự án:
```powershell
# Thiết lập đường dẫn JDK 21 (nếu chưa cài biến môi trường hệ thống)
$env:JAVA_HOME = "C:\Users\DGC\.jdks\jdk-21"
$env:Path = "$env:JAVA_HOME\bin;$env:Path"

# Di chuyển vào thư mục demo và khởi động backend
cd demo
.\mvnw.cmd spring-boot:run
```
Backend sẽ khởi chạy tại: `http://localhost:8080`

### 6.3. Khởi động Frontend (React - Port 5173)

Mở một cửa sổ dòng lệnh mới:
```bash
cd sbom-frontend
npm install
npm run dev
```
Truy cập giao diện tại: `http://localhost:5173`

### 6.4. Chạy Agent giám sát máy chủ Node.js (Tùy chọn)

Chạy start-capture.ps1 trong dự án đích để bật agent cho npm hoặc pnpm. [Lệnh thu backend và ghép phiên](HUONG_DAN_KIEM_CHUNG_SBOM.md)

---

## 7. Hướng Dẫn Thực Hiện Kịch Bản Demo (Pha 1 & Pha 2)

### Pha 1: Xác Thực Nguồn Gốc và Chuẩn Hóa SBOM Tĩnh
1. Truy cập mục **SBOM Provenance** tại thanh menu bên trái (`/provenance`).
2. Chọn tệp SBOM thô ban đầu (ví dụ: `KickZone-sbom-cyclonedx.json` hoặc `thingsboard-sbom-cyclonedx.json`).
3. Bấm **Bắt Đầu Xác Thực Nguồn Gốc**. Hệ thống tra metadata bản phát hành và checksum tham chiếu. Chọn tệp phát hành trong chi tiết gói để kiểm tra toàn vẹn.
4. Quan sát bảng số liệu phân loại: có checksum, thiếu phiên bản, bản phát hành chưa tìm thấy hoặc lỗi tra cứu.
5. Bấm **Mở SBOM đã lưu ở trang đối sánh** để chuyển sang Pha 2. SBOM được lưu trong trình duyệt hiện tại. Nút **Tải SBOM Đã Chuẩn Hóa** dùng để xuất bản JSON.

### Pha 2: Đối Soát Đa Nguồn Giữa SBOM Chuẩn Hóa và Runtime
1. Cài thư viện bộ thu thập bằng `npm ci --prefix scripts/runtime-collector` từ thư mục gốc dự án. Dùng Chrome đã cài hoặc đặt `CHROME_BIN` trỏ tới Chromium trước khi khởi động backend.
2. Mở **Runtime Reconcile** (`/reconciliation`) và tải tệp SBOM chuẩn hóa từ Provenance lên Nguồn 1.
3. Nhập URL bản deploy hoặc bản chạy local tương ứng với SBOM đã chọn, rồi bấm **Run**. Bộ thu thập dùng Chromium CDP để ghi nhận tài nguyên của phiên tải trang.
4. Bấm **Thực Hiện Đối Sánh SBOM**. Mở hai cây phụ thuộc hoặc bấm tên gói trong bảng để đọc chi tiết. Khi phiên runtime chỉ có danh sách gói, các cạnh thiếu bằng chứng được đánh dấu **Chưa đủ dữ liệu đối sánh**.
5. Tải báo cáo JSON hoặc CSV, hoặc chọn **Mở phiên đối sánh đã lưu** để xem lại cặp dữ liệu trên cùng trình duyệt.

---

## 8. Danh Mục API Endpoints Chính

| Phương thức | Đường dẫn API | Chức năng |
| :--- | :--- | :--- |
| `POST` | `/api/provenance/validate-and-normalize` | Tiếp nhận file SBOM, xác thực kho lưu trữ và gắn pedigree |
| `POST` | `/api/provenance/validate-and-normalize-json` | Tiếp nhận chuỗi JSON SBOM trực tiếp để chuẩn hóa |
| `POST` | `/api/provenance/export-enriched` | Xuất và tải về file SBOM CycloneDX đã làm giàu nguồn gốc |
| `POST` | `/api/reconciliation/generate-runtime-sbom` | Kích hoạt quét Chromium CDP và bộ nhớ V8 để tạo SBOM runtime |
| `POST` | `/api/reconciliation/poc/match` | Đối soát ma trận 2 chiều giữa SBOM tĩnh và dữ liệu runtime |
| `POST` | `/api/reconciliation/poc/export-csv` | Xuất kết quả đối soát ra file báo cáo bảng CSV |
| `GET` | `/api/reconciliation/live-f12-stream/sse` | Luồng sự kiện Server-Sent Events (SSE) đẩy dữ liệu F12 thời gian thực |
| `POST` | `/api/reconciliation/node-agent-collector` | Tiếp nhận báo cáo module nạp trong bộ nhớ từ Node.js Agent |
