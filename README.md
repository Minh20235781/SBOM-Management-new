# Nền Tảng Phân Tích Rủi Ro và Quản Lý SBOM Trong Quy Trình DevOps (GR2)

> **Đồ Án Tốt Nghiệp 2 (GR2)**: *Xây dựng website quản lý thông tin của các hệ thống theo quy trình DevOps dựa trên SBOM - Nguồn gốc và chính sách*  
> **Sinh viên thực hiện**: Nguyễn Nhật Minh (MSSV: 20235781)  
> **Đơn vị đào tạo**: Trường Công nghệ Thông tin & Truyền thông - Đại học Bách khoa Hà Nội (HUST)

---

## 1. Giới Thiệu Tổng Quan

Trong quy trình phát triển và vận hành phần mềm hiện đại (DevSecOps), danh mục thành phần phần mềm (Software Bill of Materials - SBOM) đóng vai trò cốt lõi trong việc quản lý chuỗi cung ứng phần mềm. Tuy nhiên, các giải pháp SBOM truyền thống hiện nay đang đối mặt với hai thách thức lớn:
1. **Thiếu thông tin nguồn gốc và tính toàn vẹn (Static Provenance Gap)**: Các file SBOM trích xuất từ file manifest (như `package.json`, `pom.xml`) thường thiếu thông tin phả hệ nguồn gốc (`pedigree`), dễ bị tấn công hoán đổi tên gói (typosquatting) hoặc giả mạo phiên bản.
2. **Điểm mù giữa khai báo tĩnh và vận hành thực tế (Runtime Blind Spot)**: Các file manifest chứa hàng trăm thư viện dư thừa hoặc chỉ phục vụ kiểm thử (dev dependencies), trong khi các thư viện nạp ngầm, phụ thuộc cấp hai nạp qua mạng (CDN) hoặc sinh ra trong bộ nhớ lại không hề có trong file manifest tĩnh.

Hệ thống **SBOM Risk Analysis Platform (Phiên bản GR2)** giải quyết trọn vẹn hai bài toán trên thông qua hai trục công nghệ chủ đạo:
* **Nhánh 1 - Xác thực nguồn gốc và chuẩn hóa SBOM tĩnh (SBOM Provenance & Normalization)**: Chuẩn hóa Package URL (purl), đối chiếu kho lưu trữ chính thức (npm Registry, Maven Central), truy xuất mã nguồn GitHub, xác thực mã băm SHA-256 toàn vẹn và đóng gói trường `pedigree` theo chuẩn CycloneDX.
* **Nhánh 2 - Thu thập đa tầng và đối soát đa nguồn (Runtime Instrumentation & Reconciliation)**: Ứng dụng Chrome DevTools Protocol (CDP) và hook máy chủ Node.js (`Module._load`) để bóc tách thư viện chạy ngầm trong bộ nhớ Engine V8, đối soát tự động với SBOM tĩnh để phân loại thành 4 nhóm trạng thái: `MATCHED`, `STATIC ONLY`, `RUNTIME ONLY`, `UNRESOLVED`.

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

### 3.1. Xác thực nguồn gốc và chuẩn hóa SBOM tĩnh (`/provenance`)
* **Kiểm soát tệp đầu vào**: Tự động phát hiện các tệp SBOM đã được chuẩn hóa trước đó (`devops.provenance.normalized = true`) để ngăn chặn việc nạp trùng và bảo toàn tính toàn vẹn dữ liệu.
* **Chuẩn hóa định danh (PURL)**: Tự động phân tích và quy chuẩn chuỗi Package URL đúng chuẩn hệ sinh thái (`pkg:npm/...`, `pkg:maven/...`).
* **Đối chiếu kho lưu trữ chính thức**: Tự động gọi API kho phân phối chính thức (`registry.npmjs.org`, `search.maven.org`) để kiểm tra tính tồn tại của phiên bản và kéo mã băm toàn vẹn chính thức (`dist.integrity`, `dist.shasum`).
* **Xác thực toàn vẹn bằng SHA-256**: Tính toán mã băm tệp đầu vào và mã băm phả hệ (`pedigree_digest_sha256`) theo mô hình tiện ích hệ thống `sha256sum` chuẩn FIPS-180-4.
* **Làm giàu trường `pedigree` theo CycloneDX**: Tự động bổ sung các khối `commits` (Commit SHA, Release tag, tác giả), `ancestors`, `hashes` và `notes` vào tài liệu CycloneDX xuất ra.

### 3.2. Thu thập dữ liệu Runtime đa tầng
* **Tầng Client & Mạng (Browser)**: Sử dụng Chromium CDP (`cdp-scanner.js`) tự động khởi chạy trình duyệt không đầu (headless browser), kích hoạt Performance Ledger, chụp nhật ký mạng và nạp tài nguyên.
* **Tầng Máy Chủ (Node.js Server)**: Cài đặt Node.js Runtime Agent (`nodejs-agent.js`) hook vào cơ chế `Module._load` của Node.js runtime, ghi nhận từng module được nạp vào bộ nhớ Engine V8 kèm PID và đường dẫn gọi thực tế.
* **F12 Network & Memory Inspector thời gian thực**: Giao diện F12 tích hợp trực tiếp trên web hỗ trợ xem tiến trình tải Waterfall, dung lượng, thời gian đáp ứng và bóc tách gói phụ thuộc theo thời gian thực qua Server-Sent Events (SSE).

### 3.3. Bộ máy đối soát đa nguồn tự động (`/reconciliation`)
* Cổng kiểm soát Nguồn 1 chỉ tiếp nhận các tệp SBOM tĩnh **đã qua chuẩn hóa và xác thực nguồn gốc**.
* Đối chiếu ma trận 2 chiều giữa thành phần khai báo tĩnh và dữ liệu vận hành runtime, tự động phân loại thành 4 nhóm bản ghi:
  * **MATCHED**: Trùng khớp chính xác cả tên gói và phiên bản, đại diện cho bề mặt tấn công thực tế đang hoạt động.
  * **STATIC ONLY**: Khai báo tĩnh nhưng không hoạt động khi chạy, giúp loại bỏ cảnh báo giả cho mã dư thừa.
  * **RUNTIME ONLY**: Thư viện chạy ngầm nhưng không có trong manifest tĩnh ban đầu, loại bỏ điểm mù an toàn.
  * **UNRESOLVED**: Trùng tên gói nhưng lệch phiên bản giữa khai báo tĩnh và dữ liệu nạp thực tế.

---

## 4. Bảng Số Liệu Thực Nghiệm Trên 3 Dự Án Thực Tế

Hệ thống đã được kiểm chứng đối soát trên 3 dự án thực tế đại diện cho các hệ sinh thái và quy mô khác nhau:

| Dự Án | Hệ Sinh Thái | Nguồn Tĩnh | Nguồn Runtime | MATCHED | STATIC ONLY | RUNTIME ONLY | UNRESOLVED | Ý Nghĩa An Toàn Thông Tin |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: | :--- |
| **KickZone** | JavaScript, Node.js | 871 | 28 | 29 | 823 | 1 | 19 | Loại bỏ hơn 94% cảnh báo sai từ mã dư thừa, cảnh báo 19 vị trí lệch phiên bản |
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
* **Node.js**: Phiên bản 18.x trở lên
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

Để nạp agent theo dõi tiến trình nạp module máy chủ vào ứng dụng Node.js:
```bash
node -r ./scripts/nodejs-runtime-collector/nodejs-agent.js test-apps/sample-app/server.js
```

---

## 7. Hướng Dẫn Thực Hiện Kịch Bản Demo (Pha 1 & Pha 2)

### Pha 1: Xác Thực Nguồn Gốc và Chuẩn Hóa SBOM Tĩnh
1. Truy cập mục **SBOM Provenance** tại thanh menu bên trái (`/provenance`).
2. Chọn tệp SBOM thô ban đầu (ví dụ: `KickZone-sbom-cyclonedx.json` hoặc `thingsboard-sbom-cyclonedx.json`).
3. Bấm **Bắt Đầu Xác Thực Nguồn Gốc**. Hệ thống sẽ tự động tra cứu kho lưu trữ, kiểm tra mã băm SHA-256 toàn vẹn và bổ sung trường `pedigree`.
4. Quan sát bảng số liệu phân loại: Đã xác thực, Lệch version, Không tìm thấy kho.
5. Bấm **Tải SBOM Đã Chuẩn Hóa** để lưu tệp kết quả về máy tính.

### Pha 2: Đối Soát Đa Nguồn Giữa SBOM Chuẩn Hóa và Runtime
1. Truy cập mục **Runtime Reconcile** (`/reconciliation`).
2. Tại **Nguồn 1 (SBOM Cơ Sở)**: Bấm chọn tệp SBOM đã chuẩn hóa vừa tải về ở Pha 1 (hệ thống sẽ từ chối nếu nạp file thô chưa chuẩn hóa).
3. Tại **Nguồn 2 (Dữ Liệu Runtime)**: Nhập URL trang web mục tiêu (ví dụ: `https://kick-zone-web.vercel.app/` hoặc `http://localhost:4000`) và bấm **Run**.
4. Trình duyệt tự động mở và thu thập tài nguyên F12 kết hợp dữ liệu RAM từ Engine V8. Bấm mở **F12 Network và Memory Inspector** để xem chi tiết từng tệp script tải động.
5. Bấm **Thực Hiện Đối Sánh SBOM** để xuất bảng phân loại 4 trạng thái (`MATCHED`, `STATIC ONLY`, `RUNTIME ONLY`, `UNRESOLVED`) và tải báo cáo JSON / CSV.

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
