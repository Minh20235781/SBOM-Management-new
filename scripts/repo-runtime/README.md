# Thu runtime từ repo GitHub công khai

Trong trang Đối sánh, chọn **Repo công khai**, dán URL rồi bấm **Thu runtime từ repo**. Có thể thử `https://github.com/heroku/node-js-getting-started`. Với repo có nhiều ứng dụng, dán URL thư mục GitHub dạng `/tree/main/apps/api` nếu thư mục đó có package.json và package-lock.json riêng.

Máy chủ cần Linux containers và Docker CLI. Từ gốc repo công cụ, build image khi cài đặt hoặc cập nhật bộ thu:

```sh
docker build -t sbom-repo-runtime:v1 -f scripts/repo-runtime/Dockerfile .
```

Vite dev và preview phục vụ sẵn endpoint. Khi triển khai frontend tĩnh, chạy `node scripts/repo-runtime/server.mjs` trên máy worker riêng, chuyển tiếp đúng `POST /api/runtime/repository` tới `127.0.0.1:8787`, giữ header Host của người dùng và tắt proxy buffering cho endpoint. Áp dụng quyền truy cập và giới hạn lưu lượng của ứng dụng tại reverse proxy. Máy người dùng cuối chỉ cần trình duyệt.

Runner lấy commit công khai và các tarball có integrity trong npm lockfile v2/v3. Sau khi ngắt mạng, runner cài từ cache, tạo CycloneDX bằng npm, khởi động script dev hoặc start với Node preload, mở Chromium tại đường dẫn / và ghép bằng chứng theo request ID và SHA-256 của SBOM tĩnh. Với ứng dụng thiếu version, phiên bản thành phần gốc trong SBOM mang hậu tố git và mã commit. Các gói phụ thuộc giữ phiên bản từ lockfile.

Mỗi phiên có một container dùng một lần. Runner giới hạn một phiên đồng thời, 1 CPU, 2 GiB RAM và bốn phút cho toàn phiên. Sau khi ngắt mạng, CDN, database từ xa và các dịch vụ bên ngoài sẽ không truy cập được. Phiên hiện dùng Node 24, thử các cổng 3000, 5173, 4000 và 8080. Những dự án cần pnpm, yarn, postinstall, nhiều dịch vụ hoặc kịch bản nghiệp vụ riêng có thể cung cấp log thu từ CI của dự án. Phiên sandbox phản ánh các module nạp trong kịch bản đã chạy, kể cả công cụ phát triển được nạp bởi script dev.
