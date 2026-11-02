package com.example.sbom.service.reconciliation;

import com.example.sbom.dto.reconciliation.CompareSbomsRequest;
import com.example.sbom.dto.reconciliation.RuntimePackageItem;
import com.example.sbom.dto.reconciliation.RuntimeReconciliationResponse;
import com.example.sbom.repository.PackageRepository;
import com.example.sbom.repository.ProjectRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class RuntimeReconciliationServiceTest {

    private RuntimeReconciliationService reconciliationService;
    private PackageRepository packageRepository;
    private ProjectRepository projectRepository;
    private JavaReflectionRuntimeInspector reflectionInspector;
    private ReconciliationAiEngine aiEngine;

    @BeforeEach
    void setUp() {
        packageRepository = Mockito.mock(PackageRepository.class);
        projectRepository = Mockito.mock(ProjectRepository.class);
        reflectionInspector = Mockito.mock(JavaReflectionRuntimeInspector.class);
        aiEngine = new ReconciliationAiEngine(null); // uses dynamic knowledge engine

        reconciliationService = new RuntimeReconciliationService(
                packageRepository,
                projectRepository,
                reflectionInspector,
                aiEngine
        );
    }

    @Test
    void testCompareSboms_WithShadowAndVersionDrift() {
        CompareSbomsRequest req = CompareSbomsRequest.builder()
                .presetKey("SHADOW_DRIFT")
                .build();

        RuntimeReconciliationResponse resp = reconciliationService.compareSboms(req);
        assertNotNull(resp);
        assertNotNull(resp.getSummary());
        assertTrue(resp.getPackages().size() > 0);

        // Check if shadow packages exist
        boolean hasShadow = resp.getPackages().stream()
                .anyMatch(p -> "SHADOW_INJECTED".equals(p.getCategory()) && "ADDED".equals(p.getDiffType()));
        assertTrue(hasShadow, "Should identify shadow injected packages");

        // Check if AI analysis is populated for every discrepancy
        for (var p : resp.getPackages()) {
            assertNotNull(p.getAiTechnicalReason(), "AI technical reason must not be null");
            assertNotNull(p.getAiSecurityRisk(), "AI security risk must not be null");
            assertNotNull(p.getAiRemediation(), "AI remediation must not be null");
            assertNotNull(p.getAiRiskLevel(), "AI risk level must not be null");
            assertFalse(p.getAiTechnicalReason().isBlank());
        }

        // Check summary counts
        assertTrue(resp.getSummary().getAddedCount() > 0);
    }

    @Test
    void testParseSbomJson_CycloneDx() {
        String cycloneDxJson = """
                {
                  "bomFormat": "CycloneDX",
                  "specVersion": "1.4",
                  "components": [
                    {
                      "group": "org.springframework.boot",
                      "name": "spring-boot-starter-web",
                      "version": "3.2.0",
                      "type": "library"
                    },
                    {
                      "name": "custom-lib",
                      "version": "1.0.0",
                      "type": "library"
                    }
                  ]
                }
                """;

        var packages = reconciliationService.parseSbomJson(cycloneDxJson);
        assertEquals(2, packages.size());
        assertEquals("org.springframework.boot:spring-boot-starter-web", packages.get(0).getName());
        assertEquals("3.2.0", packages.get(0).getVersion());
        assertEquals("custom-lib", packages.get(1).getName());
    }
}

