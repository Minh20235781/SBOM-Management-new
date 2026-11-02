package com.example.sbom.poc;

/** Component tĩnh đã được chuẩn hóa từ SBOM (CycloneDX hoặc SPDX). */
public record StaticComponent(
        String name,
        String normalizedName,
        String version,
        String purl,
        String bomType,
        String bomRef,
        String componentType,
        String evidenceSource
) {
}

