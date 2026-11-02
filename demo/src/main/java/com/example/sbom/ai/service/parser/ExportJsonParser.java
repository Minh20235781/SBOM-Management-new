package com.example.sbom.ai.service.parser;

import com.example.sbom.dto.PackageDTO;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;

@Component
public class ExportJsonParser {

    private static final Logger log = LoggerFactory.getLogger(ExportJsonParser.class);
    private final ObjectMapper mapper = new ObjectMapper();

    public List<PackageDTO> parseExportJson(JsonNode root) {
        List<PackageDTO> packages = new ArrayList<>();

        if (!root.isArray()) {
            throw new IllegalArgumentException("JSON should be an array of packages");
        }

        log.info("Parsing export format with {} elements", root.size());

        for (JsonNode node : root) {
            try {
                PackageDTO pkg = parsePackageNode(node);
                if (pkg != null && pkg.getName() != null) {
                    packages.add(pkg);
                }
            } catch (Exception e) {
                log.warn("Failed to parse package node: {}", e.getMessage());
            }
        }

        log.info("Successfully parsed {} packages", packages.size());
        return packages;
    }

    private PackageDTO parsePackageNode(JsonNode node) {
        PackageDTO pkg = new PackageDTO();

        // Map các field từ export format
        pkg.setRepoName(getStringValue(node, "repo_name"));
        pkg.setName(getStringValue(node, "package_name"));
        pkg.setVersion(getStringValue(node, "version"));
        pkg.setPurl(getStringValue(node, "purl"));
        pkg.setType(getStringValue(node, "type"));
        pkg.setRankScore(getDoubleValue(node, "rank_score"));
        pkg.setVulnerabilities(getStringValue(node, "vulnerabilities"));
        pkg.setSeverity(getStringValue(node, "severity"));
        pkg.setCvss(getCvssValue(node, "cvss"));

        // Các field không có trong export, set giá trị mặc định
        pkg.setDependencyDepth(0);
        pkg.setRepoCount(1);
        pkg.setVulnAnomaly(0.0); // Sẽ được tính sau
        pkg.setHubAnomaly(0.0);

        return pkg;
    }

    // Helper methods
    private String getStringValue(JsonNode node, String field) {
        return node.has(field) ? node.get(field).asText(null) : null;
    }

    private Double getDoubleValue(JsonNode node, String field) {
        if (!node.has(field)) return null;
        JsonNode value = node.get(field);
        if (value.isNumber()) return value.asDouble();
        if (value.isTextual()) {
            try {
                return Double.parseDouble(value.asText());
            } catch (NumberFormatException e) {
                return null;
            }
        }
        return null;
    }

    private Double getCvssValue(JsonNode node, String field) {
        if (!node.has(field)) return null;
        JsonNode value = node.get(field);

        if (value.isNumber()) {
            return value.asDouble();
        } else if (value.isTextual()) {
            String text = value.asText();
            if ("Secure".equalsIgnoreCase(text) || "None".equalsIgnoreCase(text)) {
                return 0.0;
            }
            try {
                return Double.parseDouble(text);
            } catch (NumberFormatException e) {
                return null;
            }
        }
        return null;
    }
}