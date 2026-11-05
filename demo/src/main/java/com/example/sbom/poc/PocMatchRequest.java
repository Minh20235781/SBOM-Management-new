package com.example.sbom.poc;

public record PocMatchRequest(
        Object sbomContent,
        Object harContent,
        Long projectId
) {
    public String getSbomContentAsString() {
        if (sbomContent == null) return "";
        if (sbomContent instanceof String s) return s;
        try {
            return new com.fasterxml.jackson.databind.ObjectMapper().writeValueAsString(sbomContent);
        } catch (Exception e) {
            return sbomContent.toString();
        }
    }

    public String getHarContentAsString() {
        if (harContent == null) return "";
        if (harContent instanceof String s) return s;
        try {
            return new com.fasterxml.jackson.databind.ObjectMapper().writeValueAsString(harContent);
        } catch (Exception e) {
            return harContent.toString();
        }
    }
}

