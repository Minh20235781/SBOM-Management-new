package com.example.sbom.dto;

import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class RiskyPackageDTO {
    private String packageName;
    private String version;
    private int vulnCount;
    private int highSeverity;
    private double cvssMax;
    private double rankScore;
    private int repoCount;
    private int dependencyDepth;
    private double vulnAnomaly;
    private double hubAnomaly;
    private boolean orphan;
}
