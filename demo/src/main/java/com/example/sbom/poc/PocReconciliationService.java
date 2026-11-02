package com.example.sbom.poc;

import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.List;
import java.util.Map;

@Service
@Slf4j
@RequiredArgsConstructor
public class PocReconciliationService {

    private final ObjectMapper objectMapper;

    /**
     * Đối sánh từ nội dung chuỗi JSON của SBOM tĩnh và dữ liệu HAR/Runtime JSON.
     */
    public MatchReport match(String sbomContent, String harContent) {
        List<StaticComponent> staticComponents = Collections.emptyList();
        List<RuntimeResource> runtimeResources = Collections.emptyList();

        try {
            if (sbomContent != null && !sbomContent.isBlank()) {
                staticComponents = SbomParser.parseContent(sbomContent);
            }
        } catch (Exception e) {
            log.error("Lỗi khi đọc static SBOM: {}", e.getMessage());
            throw new IllegalArgumentException("Không thể đọc static SBOM: " + e.getMessage(), e);
        }

        try {
            if (harContent != null && !harContent.isBlank()) {
                runtimeResources = HarParser.parseContent(harContent);
            }
        } catch (Exception e) {
            log.error("Lỗi khi đọc runtime HAR: {}", e.getMessage());
            throw new IllegalArgumentException("Không thể đọc runtime HAR: " + e.getMessage(), e);
        }

        return ComponentMatcher.match(staticComponents, runtimeResources);
    }

    /**
     * Đối sánh từ tệp tải lên (MultipartFile).
     */
    public MatchReport matchFiles(MultipartFile sbomFile, MultipartFile harFile) {
        String sbomContent = "";
        String harContent = "";

        try {
            if (sbomFile != null && !sbomFile.isEmpty()) {
                sbomContent = new String(sbomFile.getBytes(), StandardCharsets.UTF_8);
            }
            if (harFile != null && !harFile.isEmpty()) {
                harContent = new String(harFile.getBytes(), StandardCharsets.UTF_8);
            }
        } catch (IOException e) {
            throw new IllegalArgumentException("Lỗi đọc tệp tải lên: " + e.getMessage(), e);
        }

        return match(sbomContent, harContent);
    }

    /**
     * Đối sánh kết hợp với payload của Live F12 Network Stream.
     */
    public MatchReport matchFromLiveStream(String sbomContent, Map<String, Object> liveStreamData) {
        String harContent = "";
        try {
            if (liveStreamData != null && !liveStreamData.isEmpty()) {
                harContent = objectMapper.writeValueAsString(liveStreamData);
            }
        } catch (Exception e) {
            log.warn("Không thể chuyển đổi liveStreamData sang JSON: {}", e.getMessage());
        }
        return match(sbomContent, harContent);
    }

    /**
     * Xuất kết quả đối sánh ra mảng byte CSV có UTF-8 BOM.
     */
    public byte[] exportCsvBytes(MatchReport report) {
        if (report == null || report.results() == null) {
            return Reporter.toCsvBytes(Collections.emptyList());
        }
        return Reporter.toCsvBytes(report.results());
    }

    /**
     * Xuất kết quả đối sánh ra chuỗi JSON.
     */
    public String exportJsonString(MatchReport report) throws IOException {
        return Reporter.toJsonString(report);
    }
}

