package com.example.sbom.threatintel.dto;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Data;

import java.util.List;

@Data
@JsonIgnoreProperties(ignoreUnknown = true)
public class KevResponse {

    private List<KevVulnerability> vulnerabilities;

    @Data
    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class KevVulnerability {
        @JsonProperty("cveID")
        private String cveID;
    }
}
