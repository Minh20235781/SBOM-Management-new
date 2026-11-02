package com.example.sbom.poc;

public record PocMatchRequest(
        String sbomContent,
        String harContent,
        Long projectId
) {
}

