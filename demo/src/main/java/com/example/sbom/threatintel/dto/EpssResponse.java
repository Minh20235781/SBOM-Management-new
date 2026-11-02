package com.example.sbom.threatintel.dto;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import lombok.Data;

import java.util.List;

@Data
@JsonIgnoreProperties(ignoreUnknown = true)
public class EpssResponse {

    private List<EpssData> data;

    @Data
    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class EpssData {
        private String cve;
        private String epss;
    }
}
