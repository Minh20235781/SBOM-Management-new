package com.example.sbom.controller;

import com.example.sbom.entity.PackageEntity;
import com.example.sbom.entity.VulnerabilityEntity;
import com.example.sbom.repository.PackageRepository;
import com.example.sbom.repository.VulnerabilityRepository;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;
import java.util.*;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api/sbom-table")
@RequiredArgsConstructor
public class SbomTableController {

    private final PackageRepository packageRepository;
    private final VulnerabilityRepository vulnerabilityRepository;
    private final ObjectMapper objectMapper = new ObjectMapper();
    private final String exportDir = "D:\\sbom_export";

    // GET tất cả packages + vulnerabilities theo flattened table
    @GetMapping
    public List<Map<String, Object>> getSbomTable(@RequestParam(required = false) String repoName) {
        // Normalize repoName if a full URL was provided
        if (repoName != null && !repoName.isBlank()) {
            String rn = repoName.trim();
            if (rn.contains("/")) {
                String[] parts = rn.split("/");
                rn = parts[parts.length - 1];
            }
            rn = rn.replaceAll("\\.git$", "");
            repoName = rn;
        }

        List<PackageEntity> packages = (repoName == null || repoName.isEmpty())
                ? packageRepository.findAllWithVulnerabilities()
                : packageRepository.findAllByRepoWithVulnerabilities(repoName);
        List<Map<String, Object>> result = new ArrayList<>();

        for (PackageEntity pkg : packages) {
            // Explicitly load vulnerabilities from repository to ensure values are present
            List<VulnerabilityEntity> vulns = vulnerabilityRepository.findByPkg(pkg);
            if (vulns == null || vulns.isEmpty()) {
                result.add(buildRow(pkg, null));
            } else {
                for (VulnerabilityEntity v : vulns) {
                    result.add(buildRow(pkg, v));
                }
            }
        }
        return result;
    }

    private Map<String, Object> buildRow(PackageEntity pkg, VulnerabilityEntity v) {
        Map<String, Object> row = new LinkedHashMap<>();
        row.put("repo_name", pkg.getRepoName());
        row.put("package_name", pkg.getName());
        row.put("version", pkg.getVersion());
        row.put("purl", pkg.getPurl());
        row.put("type", pkg.getType());
        row.put("rank_score", pkg.getRankScore());
        if (v != null) {
            row.put("vulnerabilities", v.getVulnId());
            row.put("severity", v.getSeverity());
            row.put("cvss", v.getCvssScore());
        } else {
            row.put("vulnerabilities", null);
            row.put("severity", null);
            row.put("cvss", null);
        }
        return row;
    }

    // Export CSV
    @GetMapping("/export/csv")
    public ResponseEntity<byte[]> exportCsv(@RequestParam(required = false) String repoName) throws IOException {
        List<Map<String, Object>> data = getSbomTable(repoName);
        if (data.isEmpty()) return ResponseEntity.noContent().build();

        List<String> keys = new ArrayList<>(data.get(0).keySet());
        StringBuilder sb = new StringBuilder();
        sb.append(String.join(",", keys)).append("\n");
        for (Map<String, Object> row : data) {
            String line = keys.stream().map(k -> {
                Object o = row.get(k);
                if ("vulnerabilities".equals(k) || "severity".equals(k) || "cvss".equals(k)) {
                    if (o == null) return "Secure";
                    String s = o.toString();
                    return s.isBlank() ? "Secure" : s;
                }
                return o == null ? "" : o.toString();
            }).collect(Collectors.joining(","));
            sb.append(line).append("\n");
        }

        byte[] bytes = sb.toString().getBytes(java.nio.charset.StandardCharsets.UTF_8);
        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=sbom.csv")
                .header(HttpHeaders.CONTENT_TYPE, "text/csv; charset=utf-8")
                .body(bytes);
    }

    // Export JSON
    @GetMapping("/export/json")
    public ResponseEntity<byte[]> exportJson(@RequestParam(required = false) String repoName) throws IOException {
        List<Map<String, Object>> data = getSbomTable(repoName);
        if (data.isEmpty()) return ResponseEntity.noContent().build();
        // Replace null/blank for specific export fields with "Secure"
        for (Map<String, Object> row : data) {
            replaceNullExportField(row, "vulnerabilities");
            replaceNullExportField(row, "severity");
            replaceNullExportField(row, "cvss");
        }
        byte[] jsonBytes = objectMapper.writerWithDefaultPrettyPrinter().writeValueAsBytes(data);
        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=sbom.json")
                .header(HttpHeaders.CONTENT_TYPE, "application/json; charset=utf-8")
                .body(jsonBytes);
    }

    private void replaceNullExportField(Map<String, Object> row, String key) {
        Object o = row.get(key);
        if (o == null) {
            row.put(key, "Secure");
            return;
        }
        String s = o.toString();
        if (s.isBlank()) {
            row.put(key, "Secure");
        }
    }
}
