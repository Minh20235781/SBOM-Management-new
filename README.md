# SBOM Risk Analysis - Hướng Dẫn Cài Đặt & Chạy Dự Án

## Giới Thiệu

Dự án phân tích rủi ro SBOM (Software Bill of Materials) với 4 thành phần chính:

| Thành phần | Công nghệ | Cổng | Mô tả |
|------------|-----------|------|-------|
| Frontend | React + Vite | 5173 | Giao diện web dashboard |
| Backend | Spring Boot (Java 21) | 8080 | API xử lý chính |
| GNN Service | Python + FastAPI | 8000 | Inference với GAT/GCN |
| RF Service | Python + FastAPI | 8002 | RandomForest ML inference |

---

## Yêu Cầu Hệ Thống

### 1. Node.js
- **Yêu cầu:** Node.js >= 18.x
- **Kiểm tra:** `node -v`
- **Cài đặt:** [https://nodejs.org/](https://nodejs.org/)

### 2. Java Development Kit (JDK)
- **Yêu cầu:** JDK 17
- **Kiểm tra:** `java -version`
- **Cài đặt:** [https://adoptium.net/](https://adoptium.net/) (Eclipse Temurin 17)

### 3. Apache Maven
- **Yêu cầu:** Maven 3.8+
- **Kiểm tra:** `mvn -version`
- **Cài đặt:** [https://maven.apache.org/](https://maven.apache.org/)

### 4. Python
- **Yêu cầu:** Python 3.10 - 3.12
- **Kiểm tra:** `python --version`
- **Cài đặt:** [https://www.python.org/](https://www.python.org/)

### 5. MySQL (Optional - cho lưu trữ dữ liệu)
- **Yêu cầu:** MySQL 8.0+
- **Kiểm tra:** `mysql --version`
- **Cài đặt:** [https://dev.mysql.com/downloads/mysql/](https://dev.mysql.com/downloads/mysql/)

---

## Cài Đặt Chi Tiết

### Bước 1: Clone/Download Dự Án

```bash
git clone <repo-url>
cd GR_PROJECT
```

### Bước 2: Cài Đặt Frontend

```bash
cd sbom-frontend
npm install
```

**Lưu ý:** Nếu gặp lỗi version, sử dụng:
```bash
npm install --force
```

### Bước 3: Cài Đặt Python Dependencies

```bash
cd gnn-training
pip install torch torch-geometric fastapi uvicorn pydantic joblib numpy
```

Hoặc cài từ requirements (nếu có):
```bash
pip install -r requirements.txt
```

### Bước 4: Cài Đặt Backend (Spring Boot)

Không cần cài đặt thủ công - Maven sẽ tự động tải dependencies khi chạy.

---

## Chạy Dự Án

### Thứ Tự Khởi Động Quan Trọng

**Luôn khởi động theo thứ tự:**
1. **GNN Service** (port 8000)
2. **RF Service** (port 8002)
3. **Backend** (port 8080)
4. **Frontend** (port 5173)

---

### Cách 1: Sử Dụng Script Tự Động (Khuyến nghị)

```powershell
# Chạy 2 service ML cùng lúc
powershell -ExecutionPolicy Bypass -File .\start_ml_services.ps1
```

Script sẽ mở 2 cửa sổ PowerShell mới cho GNN và RF service.

---

### Cách 2: Chạy Từng Service Thủ Công

#### 2.1. GNN Service (Graph Neural Network)

```bash
cd gnn-training
uvicorn api.server:app --host 0.0.0.0 --port 8000
```

**Kiểm tra hoạt động:**
```bash
curl http://localhost:8000/health
```

#### 2.2. RandomForest Service

```bash
cd gnn-training
uvicorn api.rf_server:app --host 0.0.0.0 --port 8002
```

**Kiểm tra hoạt động:**
```bash
curl http://localhost:8002/health
```

---

#### 2.3. Backend (Spring Boot)

```bash
cd demo
mvn spring-boot:run
```

Hoặc build rồi chạy JAR:
```bash
mvn clean package -DskipTests
java -jar target/demo-0.0.1-SNAPSHOT.jar
```

**Kiểm tra hoạt động:**
```bash
curl http://localhost:8080/api/health
```

*Lưu ý:* Backend cần cổng 8000 và 8002 của ML services đang chạy để gọi AI inference.

---

#### 2.4. Frontend (React)

```bash
cd sbom-frontend
npm run dev
```

Mở trình duyệt: **http://localhost:5173**

---

## Cấu Hình Môi Trường (Optional)

### Biến môi trường cho ML Services

```bash
# RandomForest model paths
$env:RF_MODEL_PATH = "ml-zenodo-a/rf/random_forest_sbom_real_v2.pkl"
$env:RF_SCALER_PATH = "ml-zenodo-a/rf/scaler_real_v2.pkl"

# GNN model path (nếu cần)
$env:GNN_MODEL_PATH = "models/your_model.pt"
```

### Cấu hình Backend (application.properties)

File: `demo/src/main/resources/application.properties`

```properties
# Database (nếu sử dụng MySQL)
spring.datasource.url=jdbc:mysql://localhost:3306/sbom_db
spring.datasource.username=root
spring.datasource.password=your_password

# ML Services
ml.gnn.url=http://localhost:8000
ml.rf.url=http://localhost:8002
```

---

## Cài Đặt API Keys (BẮT BUỘC)

Dự án sử dụng 2 API keys bắt buộc phải cài đặt trong environment variables.

### 1. GEMINI_API_KEY (AI Risk Analysis)

**Mục đích:** Dùng cho tính năng AI Risk Analysis (phân tích rủi ro SBOM bằng Gemini)

**Cách lấy:**
1. Truy cập [Google AI Studio](https://aistudio.google.com/app/apikey)
2. Đăng nhập Google account
3. Tạo API Key mới
4. Copy API Key

**Cách cài đặt:**

```powershell
# Windows - PowerShell (tạm thời, chỉ áp dụng cho session hiện tại)
$env:GEMINI_API_KEY="AIzaXXXXXXXXXXXXX"

# Windows - set vĩnh viễn (System Properties)
setx GEMINI_API_KEY "AIzaXXXXXXXXXXXXX"
# Cần restart terminal sau khi chạy setx
```

**Hoặc thêm trực tiếp vào file chạy Spring Boot:**

```powershell
# Tạo file run.bat trong thư mục demo
@echo off
set GEMINI_API_KEY=AIzaXXXXXXXXXXXXX
mvn spring-boot:run
```

### 2. GITHUB_TOKEN (GitHub API)

**Mục đích:** Dùng để scan private repositories, lấy thông tin vulnerability từ GitHub Advisory Database

**Cách lấy:**
1. Truy cập [GitHub Settings > Personal Access Tokens](https://github.com/settings/tokens)
2. Click "Generate new token (classic)"
3. Chọn scopes:
   - `repo` (Full repository access) - nếu cần scan private repos
   - `security_events` - để đọc GitHub Advisory Database
4. Copy token

**Cách cài đặt:**

```powershell
# Windows - PowerShell (tạm thời)
$env:GITHUB_TOKEN="ghp_XXXXXXXXXXXXXXXXXXXX"

# Windows - set vĩnh viễn
setx GITHUB_TOKEN "ghp_XXXXXXXXXXXXXXXXXXXX"
# Cần restart terminal sau khi chạy setx
```

### 3. Chạy Spring Boot với cả 2 Tokens

```powershell
# PowerShell
$env:GEMINI_API_KEY="AIzaXXXXXXXXXXXXX"
$env:GITHUB_TOKEN="ghp_XXXXXXXXXXXXXXXXXXXX"
cd demo
mvn spring-boot:run
```

Hoặc sử dụng file có sẵn `demo/run-with-token.bat`:

```powershell
cd demo
# Edit GITHUB_TOKEN trong file trước
.\run-with-token.bat
```

**Lưu ý quan trọng:**
- **KHÔNG** commit API keys vào git! File `.gitignore` đã ignore `run-with-token.bat`
- Nếu thiếu `GEMINI_API_KEY`: AI Risk Analysis sẽ trả về mock data
- Nếu thiếu `GITHUB_TOKEN`: Vẫn hoạt động nhưng không scan được private repos

---

## Xử Lý Lỗi Thường Gặp

### Lỗi: `port already in use`

Kiểm tra và kill process đang dùng port:

```powershell
# Windows
netstat -ano | findstr :8000
taskkill /PID <process_id> /F
```

### Lỗi: `ModuleNotFoundError`

```bash
pip install <module-name>
```

### Lỗi: `npm ERR! network`

```bash
npm config set registry https://registry.npmmirror.com
npm install
```

### Lỗi: Maven build fail

```bash
cd demo
mvn clean install -U
```

---

## Kiến Trúc Hệ Thống

```
┌─────────────────────────────────────────────────────────┐
│                      Frontend                           │
│                  http://localhost:5173                   │
│                  React + Vite                           │
└───────────────────────┬─────────────────────────────────┘
                        │ HTTP
                        ▼
┌─────────────────────────────────────────────────────────┐
│                      Backend                             │
│                  http://localhost:8080                  │
│                 Spring Boot 3.5                         │
│                          │                              │
│         ┌────────────────┴────────────────┐             │
│         ▼                                 ▼             │
│  ┌─────────────┐               ┌─────────────┐          │
│  │ GNN Service│               │  RF Service │          │
│  │ :8000       │               │  :8002      │          │
│  │ GAT/GCN     │               │ RandomForest │          │
│  └─────────────┘               └─────────────┘          │
└─────────────────────────────────────────────────────────┘
```

---

## API Endpoints

### Backend (Spring Boot) - Port 8080

| Method | Endpoint | Mô tả |
|--------|----------|-------|
| GET | `/api/health` | Health check |
| POST | `/api/sbom/parse` | Parse SBOM file |
| POST | `/api/ai/risk` | AI Risk Analysis (GNN) |
| POST | `/api/ai/score` | ML Score (RandomForest) |

### GNN Service - Port 8000

| Method | Endpoint | Mô tả |
|--------|----------|-------|
| GET | `/health` | Health check |
| POST | `/predict` | GNN prediction |
| POST | `/explainability` | Explain GNN results |
| POST | `/propagation` | Risk propagation |

### RF Service - Port 8002

| Method | Endpoint | Mô tả |
|--------|----------|-------|
| GET | `/health` | Health check |
| POST | `/predict` | RandomForest prediction |

---

## Stop Services

Để dừng tất cả services:

```powershell
# Kill Python uvicorn processes
Get-Process python | Stop-Process -Force
# Hoặc đóng cửa sổ PowerShell đã mở

# Kill Java Spring Boot
Get-Process java | Stop-Process -Force

# Kill Node.js
Get-Process node | Stop-Process -Force
```
