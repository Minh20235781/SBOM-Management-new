package com.example.sbom.dto.reconciliation;

import com.example.sbom.dto.VulnerabilityDTO;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class AiDiffEvaluationRequest {
    private String packageName;
    private String declaredVersion;
    private String runtimeVersion;
    private String category; // SHADOW_INJECTED, DEAD_OR_UNUSED, BUILD_TEST_ONLY, VERSION_DRIFT, MATCHED_RUNNING
    private String diffType; // ADDED, REMOVED, MODIFIED, UNCHANGED
    private String buildScope;
    private Integer loadedClassesCount;
    private String runtimeSource;
    private List<VulnerabilityDTO> vulnerabilities;
    private String customUserPrompt;
}

