package com.example.sbom.service.reconciliation;

import com.example.sbom.ai.service.gemini.client.GeminiApiClient;
import com.example.sbom.dto.VulnerabilityDTO;
import com.example.sbom.dto.reconciliation.AiDiffEvaluationRequest;
import com.example.sbom.dto.reconciliation.AiDiffEvaluationResponse;
import com.example.sbom.dto.reconciliation.ReconciledPackageDTO;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Locale;

/**
 * AI Security & Supply Chain Engine chuyên đánh giá chi tiết từng điểm khác biệt giữa 2 file SBOM.
 * Không sử dụng text tĩnh lặp lại, mà tạo ra phân tích bảo mật sâu, rủi ro kỹ thuật,
 * và hướng dẫn khắc phục cụ thể theo phong cách Lập trình viên / DevSecOps.
 */
@Service
@RequiredArgsConstructor
public class ReconciliationAiEngine {

    private static final Logger log = LoggerFactory.getLogger(ReconciliationAiEngine.class);

    private final GeminiApiClient geminiApiClient;
    private final ObjectMapper objectMapper = new ObjectMapper();

    /**
     * Đánh giá AI chi tiết cho một điểm khác biệt cụ thể
     */
    public AiDiffEvaluationResponse evaluateDiff(AiDiffEvaluationRequest req) {
        // 1. Thử gọi Gemini AI nếu có API Key
        if (geminiApiClient != null && geminiApiClient.isApiKeyConfigured()) {
            try {
                return callGeminiForDiff(req);
            } catch (Exception e) {
                log.warn("Gemini call failed for diff package {}, falling back to knowledge engine: {}",
                        req.getPackageName(), e.getMessage());
            }
        }

        // 2. Sử dụng Dynamic DevSecOps Knowledge Engine thế hệ mới (tạo đánh giá kỹ thuật chuyên sâu theo package)
        return generateDynamicKnowledgeEvaluation(req);
    }

    /**
     * Bổ sung thông tin AI trực tiếp vào DTO của package
     */
    public void enrichPackage(ReconciledPackageDTO pkg) {
        AiDiffEvaluationRequest req = AiDiffEvaluationRequest.builder()
                .packageName(pkg.getPackageName())
                .declaredVersion(pkg.getDeclaredVersion())
                .runtimeVersion(pkg.getRuntimeVersion())
                .category(pkg.getCategory())
                .diffType(pkg.getDiffType())
                .buildScope(pkg.getBuildScope())
                .loadedClassesCount(pkg.getLoadedClassesCount())
                .runtimeSource(pkg.getRuntimeSource())
                .vulnerabilities(pkg.getVulnerabilities())
                .build();

        AiDiffEvaluationResponse eval = evaluateDiff(req);
        pkg.setAiTechnicalReason(eval.getAiTechnicalReason());
        pkg.setAiSecurityRisk(eval.getAiSecurityRisk());
        pkg.setAiRemediation(eval.getAiRemediation());
        pkg.setAiRiskLevel(eval.getAiRiskLevel());
    }

    private AiDiffEvaluationResponse callGeminiForDiff(AiDiffEvaluationRequest req) throws Exception {
        String prompt = buildPrompt(req);
        String jsonRaw = geminiApiClient.callGeminiApi(prompt);

        JsonNode root = objectMapper.readTree(jsonRaw);
        if (root.isArray() && root.size() > 0) root = root.get(0);

        String techReason = root.path("technicalReason").asText("");
        String secRisk = root.path("securityRisk").asText("");
        String remediation = root.path("developerAction").asText("");
        String level = root.path("riskLevel").asText("MEDIUM");

        if (techReason.isBlank()) {
            return generateDynamicKnowledgeEvaluation(req);
        }

        return AiDiffEvaluationResponse.builder()
                .packageName(req.getPackageName())
                .diffType(req.getDiffType())
                .category(req.getCategory())
                .aiRiskLevel(level.toUpperCase(Locale.ROOT))
                .aiTechnicalReason(techReason)
                .aiSecurityRisk(secRisk)
                .aiRemediation(remediation)
                .generatedBy("GEMINI_AI")
                .build();
    }

    private String buildPrompt(AiDiffEvaluationRequest req) {
        return String.format("""
                Bạn là Kiến trúc sư An ninh Phần mềm và Chuỗi cung ứng (Software Supply Chain Security Architect).
                Hãy phân tích điểm khác biệt cụ thể giữa 2 SBOM (Build vs Runtime hoặc SBOM v1 vs v2):
                - Tên thư viện: %s
                - Phiên bản khai báo (Build/Base): %s
                - Phiên bản thực tế (Runtime/Target): %s
                - Loại đối sánh (Category): %s
                - Loại khác biệt (diffType): %s
                - Scope khai báo: %s
                - Số classes nạp trong JVM: %s
                - Cơ chế nạp: %s
                - Danh sách CVEs: %s
                
                Hãy trả về DUY NHẤT một chuỗi JSON chuẩn:
                {
                  "technicalReason": "Giải thích nguyên nhân kỹ thuật tại sao lại có sự khác biệt này trong hệ sinh thái Java/JVM...",
                  "securityRisk": "Đánh giá chi tiết nguy cơ an ninh, bề mặt tấn công hoặc rủi ro chuỗi cung ứng...",
                  "developerAction": "Hướng dẫn cụ thể cho lập trình viên (bao gồm lệnh mvn/gradle hoặc thẻ XML/cấu hình cần sửa)...",
                  "riskLevel": "CRITICAL|HIGH|MEDIUM|LOW|INFO"
                }
                """,
                req.getPackageName(),
                req.getDeclaredVersion() != null ? req.getDeclaredVersion() : "None",
                req.getRuntimeVersion() != null ? req.getRuntimeVersion() : "None",
                req.getCategory(),
                req.getDiffType(),
                req.getBuildScope(),
                req.getLoadedClassesCount() != null ? req.getLoadedClassesCount() : 0,
                req.getRuntimeSource() != null ? req.getRuntimeSource() : "JVM",
                formatVulns(req.getVulnerabilities())
        );
    }

    /**
     * Knowledge Engine tạo phân tích sâu, linh hoạt theo từng đặc thù của thư viện, CVE và cơ chế nạp
     */
    private AiDiffEvaluationResponse generateDynamicKnowledgeEvaluation(AiDiffEvaluationRequest req) {
        String name = req.getPackageName() != null ? req.getPackageName() : "unknown-library";
        String lower = name.toLowerCase(Locale.ROOT);
        String category = req.getCategory() != null ? req.getCategory() : "UNKNOWN";
        String diffType = req.getDiffType() != null ? req.getDiffType() : "MODIFIED";
        String decVer = req.getDeclaredVersion() != null ? req.getDeclaredVersion() : "N/A";
        String runVer = req.getRuntimeVersion() != null ? req.getRuntimeVersion() : "N/A";
        int classes = req.getLoadedClassesCount() != null ? req.getLoadedClassesCount() : 1;
        String sourceMech = req.getRuntimeSource() != null ? req.getRuntimeSource() : "JVM ClassLoader";

        String techReason;
        String secRisk;
        String remediation;
        String riskLevel;

        boolean hasVulns = req.getVulnerabilities() != null && !req.getVulnerabilities().isEmpty();
        String cveNames = formatVulns(req.getVulnerabilities());

        if ("SHADOW_INJECTED".equals(category) || "ADDED".equals(diffType)) {
            // TÌNH HUỐNG 3: SHADOW INJECTION (Có trong Runtime nhưng KHÔNG có trong Build SBOM)
            if (lower.contains("log4j")) {
                techReason = String.format("Thư viện %s được nạp động từ môi trường container/server ngoài khai báo pom.xml (Nguồn: %s, %d classes).", name, sourceMech, classes);
                secRisk = "RỦI RO CỰC KỲ NGUY HIỂM: Nguy cơ Log4Shell JNDI Lookup RCE nếu phiên bản nạp là 2.x cũ. Bề mặt tấn công bị mở ngầm mà CI/CD không hề hay biết.";
                remediation = "Kiểm tra ngay thư mục lib của Tomcat/Docker image, loại bỏ các file log4j trôi nổi; khai báo tường minh trong pom.xml với version >= 2.17.1.";
                riskLevel = "CRITICAL";
            } else if (lower.contains("agent") || lower.contains("netty") || lower.contains("native") || lower.contains("asm")) {
                techReason = String.format("Mã can thiệp bytecode hoặc socket mạng được nạp thông qua JavaAgent (-javaagent) hoặc ClassLoader trung gian (%d classes).", classes);
                secRisk = "CẢNH BÁO BẤT THƯỜNG: Có khả năng là công cụ APM giám sát nhưng chưa đăng ký, hoặc mã độc tiêm nhiễm hooking vào luồng thực thi của JVM.";
                remediation = "Rà soát JVM flags khi khởi động (JAVA_TOOL_OPTIONS, -javaagent). Nếu là agent APM nội bộ, hãy bổ sung vào Build Manifest.";
                riskLevel = "HIGH";
            } else {
                techReason = String.format("Thư viện %s (%s) đang thực thi %d classes trong RAM nhưng hoàn toàn vắng mặt trong SBOM build-time (Nguồn: %s).", name, runVer, classes, sourceMech);
                secRisk = "VI PHẠM NGUYÊN TẮC ZERO TRUST: Phần mềm chạy code không qua kiểm định SBOM tại CI/CD. Gây mù lòa trước các cuộc tấn công chuỗi cung ứng.";
                remediation = "Chạy 'mvn dependency:tree' trên môi trường đóng gói; kiểm tra cấu hình maven-shade-plugin hoặc các jar copy thủ công vào runtime.";
                riskLevel = "HIGH";
            }

        } else if ("DEAD_OR_UNUSED".equals(category) || ("REMOVED".equals(diffType) && !"BUILD_TEST_ONLY".equals(category))) {
            // TÌNH HUỐNG 2b: DEAD CODE / UNUSED DEPENDENCY (Khai báo trong Build nhưng Runtime không nạp)
            if (lower.contains("commons-collections")) {
                techReason = String.format("Khai báo '%s:%s' ở scope compile trong pom.xml, tuy nhiên JVM ClassLoader ghi nhận 0 class nào được nạp vào RAM.", name, decVer);
                secRisk = hasVulns
                        ? String.format("BỀ MẶT TẤN CÔNG THỪA: Thư viện chứa lỗ hổng nghiêm trọng (%s). Dù chưa nạp, kẻ tấn công có thể kích hoạt deserialization gadget chain nếu có injection point.", cveNames)
                        : "Thư viện rác làm phình to kích thước file JAR/WAR, kéo dài thời gian build và gây nhiễu cho các công cụ quét bảo mật.";
                remediation = "Gỡ bỏ dependency khỏi pom.xml nếu không còn sử dụng. Nếu cần dùng, hãy kiểm tra Lazy Initialization của Spring.";
                riskLevel = hasVulns ? "HIGH" : "MEDIUM";
            } else {
                techReason = String.format("Thư viện '%s' được khai báo ở Build manifest nhưng không có hoạt động nạp bytecode nào trong suốt phiên chạy của JVM.", name);
                secRisk = hasVulns
                        ? String.format("Tồn tại %s nhưng không được nạp ở runtime. Mức độ rủi ro thực tế thấp hơn quét tĩnh, tuy nhiên vẫn làm ô nhiễm kho mã nguồn.", cveNames)
                        : "Code chết làm tăng attack surface lý thuyết và kích thước artifact triển khai.";
                remediation = "Chạy 'mvn dependency:analyze' để phát hiện [Unused declared dependencies] và xóa bỏ các thẻ <dependency> tương ứng.";
                riskLevel = hasVulns ? "MEDIUM" : "LOW";
            }

        } else if ("BUILD_TEST_ONLY".equals(category)) {
            // TÌNH HUỐNG 2a: BUILD/TEST ONLY (Loại trừ an toàn khỏi Production)
            techReason = String.format("Thư viện '%s:%s' mang scope '%s'. Hệ thống đóng gói (Maven/Gradle) đã loại trừ chính xác khỏi runtime artifact.", name, decVer, req.getBuildScope());
            secRisk = hasVulns
                    ? String.format("CẢNH BÁO FALSE POSITIVE: Quét tĩnh báo động lỗ hổng (%s), nhưng trên thực tế class không hề nạp vào RAM máy chủ Production.", cveNames)
                    : "An toàn tuyệt đối trên Production. Không mở ra bất kỳ bề mặt tấn công mạng nào.";
            remediation = "Giữ nguyên scope test trong pom.xml. Có thể gắn nhãn VEX (Vulnerability Exploitability eXchange) là 'not_affected (code_not_reachable)'.";
            riskLevel = "INFO";

        } else if ("VERSION_DRIFT".equals(category) || "MODIFIED".equals(diffType)) {
            // LỆCH PHIÊN BẢN (VERSION DRIFT)
            techReason = String.format("Xung đột phiên bản: Khai báo trong Build là '%s', nhưng Runtime JVM đang nạp phiên bản '%s' (%d classes).", decVer, runVer, classes);
            secRisk = "NGUY CƠ BẤT TƯƠNG THÍCH & HẠ CẤP: Có thể xảy ra hiện tượng Jar Hell, ghi đè classloader hoặc vô tình nạp phải phiên bản cũ có CVE đã vá.";
            remediation = String.format("Sử dụng <dependencyManagement> trong pom.xml hoặc 'mvn dependency:tree -Dverbose' để khóa cứng phiên bản mong muốn (%s).", decVer);
            riskLevel = "MEDIUM";

        } else {
            // TRÙNG KHỚP (MATCHED_RUNNING)
            if (hasVulns) {
                techReason = String.format("Thư viện '%s:%s' đang nạp %d classes và hoạt động trực tiếp trong RAM JVM (Nguồn: %s).", name, runVer, classes, sourceMech);
                secRisk = String.format("RỦI RO THẬT CẦN VÁ GẤP: Thư viện đang chạy thật VÀ chứa lỗ hổng active (%s). Kẻ tấn công có thể khai thác trực tiếp qua API.", cveNames);
                remediation = "Cập nhật ngay phiên bản thư viện lên bản vá mới nhất trong pom.xml và build lại Docker image.";
                riskLevel = "HIGH";
            } else {
                techReason = String.format("Khai báo Build và Runtime trùng khớp 100%% (%s). Đang nạp %d classes bình thường.", runVer, classes);
                secRisk = "Trạng thái an toàn. Không phát hiện CVE nghiêm trọng hay dấu hiệu bất thường về chuỗi cung ứng.";
                remediation = "Duy trì giám sát định kỳ trong chu trình CI/CD và theo dõi thông tin CVE mới phát sinh.";
                riskLevel = "LOW";
            }
        }

        return AiDiffEvaluationResponse.builder()
                .packageName(name)
                .diffType(diffType)
                .category(category)
                .aiRiskLevel(riskLevel)
                .aiTechnicalReason(techReason)
                .aiSecurityRisk(secRisk)
                .aiRemediation(remediation)
                .generatedBy("DYNAMIC_KNOWLEDGE_ENGINE")
                .build();
    }

    private String formatVulns(List<VulnerabilityDTO> vulns) {
        if (vulns == null || vulns.isEmpty()) return "Không có CVE";
        StringBuilder sb = new StringBuilder();
        for (VulnerabilityDTO v : vulns) {
            String vId = v.getName() != null ? v.getName() : "CVE-Unknown";
            sb.append(vId)
                    .append(" (CVSS: ").append(v.getCvssScore() != null ? v.getCvssScore() : "N/A").append("), ");
        }
        return sb.toString();
    }
}
