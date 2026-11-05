package com.example.sbom.provenance;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;
import java.util.Map;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ProvenanceResultDTO {
    private boolean alreadyNormalized;
    private String message;
    private String format; // CycloneDX / SPDX
    private String specVersion;
    private int totalComponents;
    private int verifiedComponents;
    private int suspiciousComponents;
    private int unverifiedComponents;
    private String fileSha256;
    private String pedigreeDigestSha256;
    private String sha256Engine;
    private List<ComponentProvenanceDTO> components;
    private Map<String, Object> enrichedSbomJson;
}

