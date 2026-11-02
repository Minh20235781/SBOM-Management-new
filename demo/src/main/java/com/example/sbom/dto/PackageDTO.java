package com.example.sbom.dto;

import lombok.Data;
import com.fasterxml.jackson.annotation.JsonInclude;

@Data
@JsonInclude(JsonInclude.Include.NON_NULL)
public class PackageDTO {
    private String name;
    private String version;
    private String repoName;
    private String purl;
    private String type;
    private Double rankScore;
    private String vulnerabilities;
    private String severity;
    private Double cvss;
    private Integer dependencyDepth;
    private Integer repoCount;
    private Double vulnAnomaly;
    private Double hubAnomaly;
}
