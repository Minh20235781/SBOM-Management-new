package com.example.sbom.poc;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import com.fasterxml.jackson.databind.SerializationFeature;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;

public final class Reporter {

    private static final ObjectMapper MAPPER = new ObjectMapper()
            .setPropertyNamingStrategy(PropertyNamingStrategies.SNAKE_CASE)
            .enable(SerializationFeature.INDENT_OUTPUT);

    private static final List<String> CSV_HEADER = List.of(
            "status", "component", "static_version", "runtime_resource",
            "runtime_version", "version_status", "evidence");

    private Reporter() {
    }

    private static void ensureParent(Path path) throws IOException {
        Path parent = path.toAbsolutePath().getParent();
        if (parent != null) {
            Files.createDirectories(parent);
        }
    }

    /** Lưu báo cáo JSON (giữ nguyên ký tự Unicode). */
    public static void saveJson(Object data, Path outputPath) throws IOException {
        ensureParent(outputPath);
        MAPPER.writeValue(outputPath.toFile(), data);
    }

    /** Chuyển dữ liệu sang chuỗi JSON có thụt dòng. */
    public static String toJsonString(Object data) throws IOException {
        return MAPPER.writeValueAsString(data);
    }

    private static String csvCell(String value) {
        if (value == null) {
            return "";
        }
        if (value.contains(",") || value.contains("\"")
                || value.contains("\n") || value.contains("\r")) {
            return "\"" + value.replace("\"", "\"\"") + "\"";
        }
        return value;
    }

    /** Tạo chuỗi CSV có UTF-8 BOM để Excel hiển thị tiếng Việt đúng. */
    public static String toCsvString(List<MatchResult> results) {
        StringBuilder sb = new StringBuilder("\uFEFF");
        sb.append(String.join(",", CSV_HEADER)).append("\r\n");

        if (results != null) {
            for (MatchResult r : results) {
                sb.append(csvCell(r.status())).append(',')
                  .append(csvCell(r.component())).append(',')
                  .append(csvCell(r.staticVersion())).append(',')
                  .append(csvCell(r.runtimeResource())).append(',')
                  .append(csvCell(r.runtimeVersion())).append(',')
                  .append(csvCell(r.versionStatus())).append(',')
                  .append(csvCell(r.evidence())).append("\r\n");
            }
        }
        return sb.toString();
    }

    public static byte[] toCsvBytes(List<MatchResult> results) {
        return toCsvString(results).getBytes(StandardCharsets.UTF_8);
    }

    /** Lưu bảng đối sánh thành CSV (UTF-8 có BOM). */
    public static void saveCsv(List<MatchResult> results, Path outputPath) throws IOException {
        ensureParent(outputPath);
        Files.writeString(outputPath, toCsvString(results), StandardCharsets.UTF_8);
    }

    /** Hiển thị kết quả tổng hợp trên terminal. */
    public static void printSummary(MatchReport.Summary summary) {
        System.out.println("\n========== MATCHING SUMMARY ==========");
        System.out.println("Số component tĩnh: " + summary.staticComponentCount());
        System.out.println("Số tài nguyên runtime: " + summary.runtimeResourceCount());
        System.out.println("Số dòng kết quả: " + summary.resultCount());

        for (Map.Entry<String, Integer> e : summary.statusCounts().entrySet()) {
            System.out.println(e.getKey() + ": " + e.getValue());
        }
        System.out.println("======================================\n");
    }
}

