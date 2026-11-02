package com.example.sbom.poc;

/** Một dòng kết quả đối sánh. */
public record MatchResult(
        String status,
        String component,
        String staticVersion,
        String runtimeResource,
        String runtimeVersion,
        String versionStatus,
        String evidence
) {
}

