package com.example.sbom.dto;

import lombok.Data;

@Data
public class ValidationIssueDTO {
    private String type;
    private String packageName;
    private String severity;
    private String description;
    private String comparisonScope;
}
