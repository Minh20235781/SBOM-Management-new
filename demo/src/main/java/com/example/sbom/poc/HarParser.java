package com.example.sbom.poc;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

public final class HarParser {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private HarParser() {
    }

    /** Phân loại sơ bộ tài nguyên dựa trên MIME type và phần mở rộng URL. */
    public static String inferResourceType(String path, String mimeType) {
        String mime = mimeType == null ? "" : mimeType.toLowerCase(Locale.ROOT);
        String p = path == null ? "" : path.toLowerCase(Locale.ROOT);

        if (mime.contains("javascript") || p.endsWith(".js") || p.endsWith(".mjs")) {
            return "javascript";
        }
        if (mime.contains("text/css") || p.endsWith(".css")) {
            return "stylesheet";
        }
        if (mime.contains("text/html") || p.endsWith(".html")) {
            return "document";
        }
        if (mime.startsWith("image/")
                || p.endsWith(".png") || p.endsWith(".jpg") || p.endsWith(".jpeg")
                || p.endsWith(".gif") || p.endsWith(".svg") || p.endsWith(".webp")
                || p.endsWith(".ico")) {
            return "image";
        }
        if (mime.startsWith("font/")
                || p.endsWith(".woff") || p.endsWith(".woff2")
                || p.endsWith(".ttf") || p.endsWith(".otf")) {
            return "font";
        }
        if (mime.contains("json")) {
            return "api_or_json";
        }
        return "other";
    }

    private static String text(JsonNode node, String field) {
        if (node == null) return null;
        JsonNode value = node.get(field);
        return (value != null && value.isTextual()) ? value.asText() : null;
    }

    /** Phân tích JsonNode chứa dữ liệu HAR hoặc mảng entries. */
    public static List<RuntimeResource> parseJson(JsonNode root) {
        if (root == null) {
            return List.of();
        }

        JsonNode entries = null;
        if (root.isObject()) {
            if (root.has("log") && root.path("log").has("entries")) {
                entries = root.path("log").path("entries");
            } else if (root.has("entries")) {
                entries = root.get("entries");
            } else if (root.has("resources")) {
                entries = root.get("resources");
            } else if (root.has("auditLog") && root.path("auditLog").has("entries")) {
                entries = root.path("auditLog").path("entries");
            } else if (root.has("auditLog") && root.path("auditLog").has("requests")) {
                entries = root.path("auditLog").path("requests");
            } else if (root.has("requests")) {
                entries = root.get("requests");
            } else if (root.has("components")) {
                entries = root.get("components");
            } else if (root.has("packages")) {
                entries = root.get("packages");
            }
        } else if (root.isArray()) {
            entries = root;
        }

        if (entries == null || !entries.isArray()) {
            return List.of();
        }

        List<RuntimeResource> results = new ArrayList<>();
        int index = 0;
        for (JsonNode entry : entries) {
            index++;
            JsonNode request = entry.path("request");
            JsonNode response = entry.path("response");

            String url = text(request, "url");
            if (url == null && entry.has("url")) {
                url = text(entry, "url");
            }
            if (url == null && entry.has("name")) {
                String pName = text(entry, "name");
                String pVer = text(entry, "version");
                if (pVer != null && !pVer.isBlank()) {
                    url = "https://cdn.jsdelivr.net/npm/" + pName + "@" + pVer + "/index.js";
                } else {
                    url = "https://cdn.jsdelivr.net/npm/" + pName + "/index.js";
                }
            }
            if (url == null || url.isBlank()) {
                continue;
            }

            String host = null;
            String path = null;
            try {
                URI uri = URI.create(url);
                host = uri.getHost();
                path = uri.getPath();
            } catch (IllegalArgumentException ignored) {
                // URL không hợp lệ: vẫn giữ lại bản ghi, chỉ thiếu host/path.
            }

            String mimeType = null;
            if (response.has("content")) {
                mimeType = text(response.path("content"), "mimeType");
            } else if (entry.has("mimeType")) {
                mimeType = text(entry, "mimeType");
            }

            Integer status = null;
            if (response.path("status").isInt()) {
                status = response.path("status").asInt();
            } else if (entry.path("status").isInt()) {
                status = entry.path("status").asInt();
            }

            String method = text(request, "method");
            if (method == null && entry.has("method")) {
                method = text(entry, "method");
            }

            String startedAt = text(entry, "startedDateTime");
            if (startedAt == null && entry.has("startedAt")) {
                startedAt = text(entry, "startedAt");
            }

            results.add(new RuntimeResource(
                    String.format("RT-%04d", index),
                    url,
                    host,
                    path,
                    method,
                    status,
                    mimeType,
                    inferResourceType(path, mimeType),
                    startedAt,
                    "browser_har"
            ));
        }
        return results;
    }

    /** Phân tích HAR từ chuỗi JSON content. */
    public static List<RuntimeResource> parseContent(String content) throws IOException {
        if (content == null || content.isBlank()) {
            return List.of();
        }
        JsonNode root = MAPPER.readTree(content);
        return parseJson(root);
    }

    /** Đọc HAR và trả về danh sách tài nguyên quan sát được từ file. */
    public static List<RuntimeResource> parse(Path filePath) throws IOException {
        if (!Files.exists(filePath)) {
            throw new java.io.FileNotFoundException("Không tìm thấy HAR: " + filePath);
        }
        return parseContent(Files.readString(filePath));
    }
}

