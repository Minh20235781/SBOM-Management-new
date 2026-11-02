package com.example.sbom.dto;

import lombok.Data;
import java.util.List;

@Data
public class PackageDetailsResponse {
    private PackageDTO packageInfo;
    private List<VulnerabilityDTO> vulnerabilities;
}
