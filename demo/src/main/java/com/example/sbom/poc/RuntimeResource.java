package com.example.sbom.poc;

/** Tài nguyên runtime quan sát được từ HAR hoặc Network capture. */
public record RuntimeResource(
        String resourceId,
        String url,
        String host,
        String path,
        String method,
        Integer status,
        String mimeType,
        String resourceType,
        String startedAt,
        String evidenceSource
) {
}

