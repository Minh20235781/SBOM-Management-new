package com.example.sbom.ai.ml.service;

import com.example.sbom.ai.ml.dto.AiRiskPredictionDTO;
import com.example.sbom.ai.ml.dto.RfPredictionResponse;
import com.example.sbom.ai.ml.util.RepoNameNormalizer;
import com.example.sbom.entity.PackageEntity;
import com.example.sbom.entity.VulnerabilityEntity;
import com.example.sbom.repository.PackageRepository;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.stereotype.Service;
import org.springframework.web.client.HttpStatusCodeException;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestTemplate;

import java.time.LocalDate;
import java.util.ArrayList;
import java.util.List;

/**
 * RandomForest prediction using the 13-feature model trained on
 * Zenodo Dataset A (60,662 packages).
 *
 * Talks to the Python rf_server.py on port 8002 with the 13-feature
 * contract from ml-zenodo-a/rf/feature_names_real.json.
 * Ecosystem is inferred from package PURL prefix.
 */
@Service
@RequiredArgsConstructor
public class ZenodoRfPredictionService {

    private static final Logger log = LoggerFactory.getLogger(ZenodoRfPredictionService.class);

    /**
     * 13-feature order — must match {@code feature_names_real.json} exactly.
     * The Python scaler enforces this via {@code scaler.n_features_in_}.
     */
    private static final List<String> FEATURE_ORDER = List.of(
            "advisory_count",       // 0
            "critical_count",       // 1
            "high_count",           // 2
            "medium_count",         // 3
            "low_count",            // 4
            "max_advisory_year",    // 5
            "rank_score",           // 6
            "ecosystem_npm",        // 7
            "ecosystem_Maven",      // 8
            "ecosystem_PyPI",       // 9
            "ecosystem_Packagist",  // 10
            "ecosystem_RubyGems",   // 11
            "ecosystem_Other"       // 12
    );
    private static final int EXPECTED_FEATURE_COUNT = FEATURE_ORDER.size();

    private final PackageRepository packageRepository;
    private final ObjectMapper objectMapper;

    @Value("${ai.rf-new.service-url:http://localhost:8002}")
    private String serviceUrl;

    @Value("${ai.rf-new.connect-timeout-ms:2000}")
    private int connectTimeoutMs;

    @Value("${ai.rf-new.timeout-seconds:120}")
    private long timeoutSeconds;

    private final RestTemplate restTemplate = new RestTemplate();

    @jakarta.annotation.PostConstruct
    public void configureTimeouts() {
        SimpleClientHttpRequestFactory factory = new SimpleClientHttpRequestFactory();
        factory.setConnectTimeout(connectTimeoutMs);
        factory.setReadTimeout((int) (timeoutSeconds * 1000L));
        restTemplate.setRequestFactory(factory);
    }

    public List<AiRiskPredictionDTO> predictForRepo(String repoName) {
        String normalizedRepo = RepoNameNormalizer.normalize(repoName);
        if (normalizedRepo == null || normalizedRepo.isBlank()) {
            throw new IllegalArgumentException("repoName is required");
        }

        List<PackageEntity> packages = loadLatestPackages(normalizedRepo);
        if (packages.isEmpty()) {
            log.warn("Zenodo RF: no packages found for repo {}", normalizedRepo);
            return List.of();
        }

        List<PredictionItem> items = new ArrayList<>();
        for (PackageEntity pkg : packages) {
            items.add(buildPredictionItem(pkg));
        }

        try {
            String requestJson = objectMapper.writeValueAsString(new PredictionRequest(items));
            String rawResponse = callPredictionService(requestJson, normalizedRepo);
            if (rawResponse == null || rawResponse.isBlank()) {
                log.warn("Zenodo RF: empty response for repo {}", normalizedRepo);
                return List.of();
            }
            RfPredictionResponse envelope = objectMapper.readValue(rawResponse, RfPredictionResponse.class);
            List<AiRiskPredictionDTO> results = envelope.getItems();
            return results == null ? List.of() : results;
        } catch (java.io.IOException ex) {
            throw new IllegalStateException("Failed to parse Zenodo RF output", ex);
        }
    }

    private String callPredictionService(String requestJson, String repoName) {
        String url = serviceUrl + "/predict";
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);

        long startMillis = System.currentTimeMillis();
        try {
            ResponseEntity<String> response = restTemplate.exchange(
                    url, HttpMethod.POST, new HttpEntity<>(requestJson, headers), String.class);
            long elapsedMs = System.currentTimeMillis() - startMillis;
            log.info("Zenodo RF HTTP done: repo={}, elapsedMs={}, status={}",
                    repoName, elapsedMs, response.getStatusCode());
            return response.getBody() != null ? response.getBody() : "";
        } catch (HttpStatusCodeException ex) {
            log.error("Zenodo RF HTTP {}: body={}", ex.getStatusCode(), ex.getResponseBodyAsString());
            throw new IllegalStateException(
                    "Zenodo RF service returned " + ex.getStatusCode() + ": "
                            + ex.getResponseBodyAsString(), ex);
        } catch (RestClientException ex) {
            log.error("Zenodo RF HTTP failure: repo={}, err={}", repoName, ex.getMessage());
            throw new IllegalStateException(
                    "Zenodo RF service unreachable at " + url
                            + " — is the rf_server.py service running on that port?",
                    ex);
        }
    }

    /**
     * Build the 13-feature vector for one package.
     * Features: advisory_count, critical/high/medium/low counts,
     * max_advisory_year, rank_score, ecosystem one-hot.
     */
    private PredictionItem buildPredictionItem(PackageEntity pkg) {
        List<VulnerabilityEntity> vulns = pkg.getVulnerabilities();
        int advisoryCount = vulns == null ? 0 : vulns.size();

        int critical = 0, high = 0, medium = 0, low = 0;
        int maxYear = 0;
        int currentYear = LocalDate.now().getYear();
        if (vulns != null) {
            for (VulnerabilityEntity v : vulns) {
                String sev = v.getSeverity();
                if (sev == null) continue;
                switch (sev.toUpperCase()) {
                    case "CRITICAL" -> critical++;
                    case "HIGH" -> high++;
                    case "MEDIUM" -> medium++;
                    case "LOW" -> low++;
                }
                Integer yr = extractYear(v);
                if (yr != null && yr > maxYear) {
                    maxYear = yr;
                }
            }
        }
        // When a package has no advisories we impute the current year so
        // max_advisory_year stays a meaningful recency signal at the model
        // boundary. The scaler was fit on data where 0-advisory packages
        // had this imputed, so keeping the behaviour consistent here.
        int maxAdvisoryYear = maxYear > 0 ? maxYear : currentYear;

        double rankScore = pkg.getRankScore() == null ? 0.0 : pkg.getRankScore();
        double[] ecosystemOneHot = ecosystemOneHot(pkg);

        List<Double> features = new ArrayList<>(EXPECTED_FEATURE_COUNT);
        features.add((double) advisoryCount);
        features.add((double) critical);
        features.add((double) high);
        features.add((double) medium);
        features.add((double) low);
        features.add((double) maxAdvisoryYear);
        features.add(rankScore);
        for (double v : ecosystemOneHot) {
            features.add(v);
        }

        if (features.size() != EXPECTED_FEATURE_COUNT) {
            log.warn("Feature length mismatch for {}: expected {}, got {}",
                    pkg.getName(), EXPECTED_FEATURE_COUNT, features.size());
        }
        return new PredictionItem(pkg.getName(), pkg.getVersion(), features);
    }

    /**
     * Map a package's PURL (or {@code type} field as fallback) to the
     * one-hot encoding used by the trained model. Mirrors
     * {@code ml-zenodo-a/data/parse_spdx.py::PURL_TYPE_TO_ECOSYSTEM}.
     */
    private static double[] ecosystemOneHot(PackageEntity pkg) {
        String eco = ecosystemOf(pkg);
        boolean isNpm        = "npm".equals(eco);
        boolean isMaven      = "maven".equals(eco);
        boolean isPyPI       = "pypi".equals(eco);
        boolean isPackagist  = "packagist".equals(eco);
        boolean isRubyGems   = "rubygems".equals(eco);
        return new double[] {
                isNpm       ? 1.0 : 0.0,
                isMaven     ? 1.0 : 0.0,
                isPyPI      ? 1.0 : 0.0,
                isPackagist ? 1.0 : 0.0,
                isRubyGems  ? 1.0 : 0.0,
                // ecosystem_Other = "any of the above five is false"
                (!isNpm && !isMaven && !isPyPI && !isPackagist && !isRubyGems) ? 1.0 : 0.0,
        };
    }

    private static String ecosystemOf(PackageEntity pkg) {
        String purl = pkg.getPurl();
        if (purl != null && purl.startsWith("pkg:")) {
            // pkg:npm/foo  -> "npm"
            String rest = purl.substring("pkg:".length());
            int slash = rest.indexOf('/');
            if (slash > 0) {
                String type = rest.substring(0, slash).toLowerCase();
                return type;
            }
        }
        // Fallback: type column from CycloneDX (e.g. "library", "npm", ...)
        String type = pkg.getType();
        if (type != null) {
            String t = type.toLowerCase();
            if (t.equals("npm") || t.equals("maven") || t.equals("pypi")
                    || t.equals("packagist") || t.equals("rubygems")) {
                return t;
            }
        }
        return "other";
    }

    /** Pull a 4-digit year out of any date string the vuln blob carries. */
    private static Integer extractYear(VulnerabilityEntity v) {
        // Vulnerabilities table doesn't store published/modified dates directly,
        // but the URL often embeds the CVE year. Best-effort only.
        String url = v.getUrl();
        if (url != null && url.length() >= 4 && Character.isDigit(url.charAt(url.length() - 4))) {
            try {
                return Integer.parseInt(url.substring(url.length() - 4));
            } catch (NumberFormatException ignore) { /* fall through */ }
        }
        // No reliable source — return null so we don't impute a bogus year.
        return null;
    }

    private List<PackageEntity> loadLatestPackages(String repoName) {
        List<PackageEntity> packages =
                packageRepository.findAllByRepoWithVulnerabilities(repoName);
        if (packages == null || packages.isEmpty()) {
            return List.of();
        }
        // Pick the latest version per package name
        java.util.Map<String, PackageEntity> latestByName = new java.util.HashMap<>();
        for (PackageEntity pkg : packages) {
            String name = pkg.getName();
            PackageEntity existing = latestByName.get(name);
            if (existing == null || compareVersions(pkg.getVersion(), existing.getVersion()) > 0) {
                latestByName.put(name, pkg);
            }
        }
        return new ArrayList<>(latestByName.values());
    }

    private static int compareVersions(String v1, String v2) {
        if (v1 == null && v2 == null) return 0;
        if (v1 == null) return -1;
        if (v2 == null) return 1;
        String[] a = v1.split("\\.");
        String[] b = v2.split("\\.");
        int len = Math.max(a.length, b.length);
        for (int i = 0; i < len; i++) {
            int ai = i < a.length ? parseLeadingInt(a[i]) : 0;
            int bi = i < b.length ? parseLeadingInt(b[i]) : 0;
            if (ai != bi) return Integer.compare(ai, bi);
        }
        return v1.compareTo(v2);
    }

    private static int parseLeadingInt(String s) {
        if (s == null) return 0;
        String num = s.replaceAll("\\D", "");
        if (num.isEmpty()) return 0;
        try { return Integer.parseInt(num); }
        catch (NumberFormatException ex) { return 0; }
    }

    private record PredictionRequest(List<PredictionItem> items) { }
    private record PredictionItem(String packageName, String version, List<Double> features) { }
}