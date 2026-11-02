package com.example.sbom.ai.service.parser;

import com.example.sbom.dto.PackageDTO;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

@Component
public class PackageParser {

    private static final Logger log = LoggerFactory.getLogger(PackageParser.class);
    private final ObjectMapper mapper = new ObjectMapper();

    public List<PackageDTO> parsePackagesFromFile(MultipartFile file) {
        try {
            JsonNode root = mapper.readTree(file.getInputStream());
            List<PackageDTO> packages = new ArrayList<>();

            if (root.isArray()) {
                for (JsonNode node : root) {
                    PackageDTO pkg = parsePackageNode(node);
                    if (pkg != null && pkg.getName() != null) {
                        packages.add(pkg);
                    }
                }
            }

            log.info("Parsed {} packages for AI analysis", packages.size());
            return packages;
        } catch (IOException e) {
            log.warn("Failed to parse packages for AI analysis: {}", e.getMessage());
            return new ArrayList<>();
        }
    }

    private PackageDTO parsePackageNode(JsonNode node) {
        PackageDTO pkg = new PackageDTO();

        // Map tất cả các field từ export
        pkg.setRepoName(node.has("repo_name") ? node.get("repo_name").asText() : null);
        pkg.setName(node.has("package_name") ? node.get("package_name").asText() : null);
        pkg.setVersion(node.has("version") ? node.get("version").asText() : null);
        pkg.setPurl(node.has("purl") ? node.get("purl").asText() : null);
        pkg.setType(node.has("type") ? node.get("type").asText() : null);
        pkg.setRankScore(node.has("rank_score") ? node.get("rank_score").asDouble() : 0.0);
        pkg.setVulnerabilities(node.has("vulnerabilities") ? node.get("vulnerabilities").asText() : null);
        pkg.setSeverity(node.has("severity") ? node.get("severity").asText() : null);

        if (node.has("cvss")) {
            parseCvssValue(node, pkg);
        }

        return pkg;
    }

    private void parseCvssValue(JsonNode node, PackageDTO pkg) {
        JsonNode cvssNode = node.get("cvss");
        if (cvssNode.isNumber()) {
            pkg.setCvss(cvssNode.asDouble());
        } else if (cvssNode.isTextual()) {
            String cvssText = cvssNode.asText();
            if (!"Secure".equalsIgnoreCase(cvssText)) {
                try {
                    pkg.setCvss(Double.parseDouble(cvssText));
                } catch (NumberFormatException e) {
                    pkg.setCvss(0.0);
                }
            }
        }
    }
}