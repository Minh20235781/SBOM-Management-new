package com.example.sbom.ai.ml.util;

public final class RepoNameNormalizer {

    private RepoNameNormalizer() {
    }

    public static String normalize(String repoName) {
        if (repoName == null) {
            return null;
        }
        String normalized = repoName.trim();
        if (normalized.contains("/")) {
            String[] parts = normalized.split("/");
            normalized = parts[parts.length - 1];
        }
        return normalized.replaceAll("\\.git$", "");
    }
}
