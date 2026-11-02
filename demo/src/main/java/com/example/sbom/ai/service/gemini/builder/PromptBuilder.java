package com.example.sbom.ai.service.gemini.builder;

import com.example.sbom.ai.dto.AnalysisFeatures;
import com.example.sbom.dto.PackageDTO;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.stream.Collectors;

@Component
public class PromptBuilder {

    public String buildSecurityAnalysisPrompt(AnalysisFeatures features, String top5RiskyPackages) {
        return String.format(
                """
                Bạn là chuyên gia bảo mật. Phân tích SBOM và đưa ra 3-5 khuyến nghị quan trọng nhất.
                
                Số liệu:
                - Packages: %d total, %d secure, %d vulnerable
                - Lỗ hổng: %d CRITICAL, %d HIGH, %d MEDIUM, %d LOW
                - Top risky: %s
                
                Trả về JSON array với format:
                [{"priority":1,"packageName":"name","currentVersion":"ver","issue":"issue","suggestion":"fix","estimatedEffort":"LOW/MEDIUM/HIGH","targetVersion":"new-ver","impactIfNotFixed":"impact","reason":"reason"}]
                
                QUAN TRỌNG: Chỉ trả về JSON, không thêm text khác. Giới hạn mỗi field 200 ký tự.""",
                features.getTotalPackages(),
                features.getSecurePackages(),
                features.getVulnerablePackages(),
                features.getCriticalCount(),
                features.getHighCount(),
                features.getMediumCount(),
                features.getLowCount(),
                top5RiskyPackages
        );
    }

    public String getTop5RiskyPackages(List<PackageDTO> packages) {
        try {
            if (packages == null || packages.isEmpty()) {
                return "None";
            }

            return packages.stream()
                    .filter(p -> p != null && p.getName() != null)
                    .sorted((a, b) -> Double.compare(
                            (b.getRankScore() != null ? b.getRankScore() : 0),
                            (a.getRankScore() != null ? a.getRankScore() : 0)
                    ))
                    .limit(5)
                    .map(p -> String.format("%s v%s", p.getName(),
                            p.getVersion() != null ? p.getVersion() : "?"))
                    .collect(Collectors.joining(", "));
        } catch (Exception e) {
            return "Error";
        }
    }
}