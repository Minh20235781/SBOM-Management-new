package com.example.sbom.dto.reconciliation;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class AiDiffEvaluationResponse {
    private String packageName;
    private String diffType;
    private String category;
    private String aiRiskLevel; // CRITICAL, HIGH, MEDIUM, LOW, INFO
    private String aiTechnicalReason;
    private String aiSecurityRisk;
    private String aiRemediation;
    private String generatedBy; // "GEMINI_AI" or "SECURITY_KNOWLEDGE_ENGINE"
}

