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
public class ComponentProvenanceDTO {
    private String name;
    private String version;
    private String purl;
    private String normalizedPurl;
    private String ecosystem; // npm, maven, etc.
    private String status; // VERIFIED, SUSPICIOUS_VERSION, NOT_FOUND, UNVERIFIED
    private String officialRegistry;
    private String officialHash;
    private String officialHashAlgorithm;
    private String componentSha256;
    private String repositoryUrl;
    private String commitSha;
    private String releaseTag;
    private String publisherOrAuthor;
    private List<String> issues;
    private Map<String, Object> pedigree;
}

