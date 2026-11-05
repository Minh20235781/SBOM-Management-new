package com.example.sbom.poc;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

public final class ComponentMatcher {

    private static final List<String> STATUSES =
            List.of("MATCHED", "STATIC_ONLY", "RUNTIME_ONLY", "UNRESOLVED");

    private ComponentMatcher() {
    }

    /** Ưu tiên tên package từ PURL npm nếu có, nếu không dùng tên component trong SBOM. */
    static String staticPackageName(StaticComponent component) {
        String purlName = Normalizer.packageNameFromPurl(component.purl());
        if (purlName != null) {
            return Normalizer.normalizePackageName(purlName);
        }
        return Normalizer.normalizePackageName(component.name());
    }

    static String compareVersion(String staticVersion, String runtimeVersion) {
        if (staticVersion == null || staticVersion.isBlank()
                || runtimeVersion == null || runtimeVersion.isBlank()) {
            return "VERSION_UNKNOWN";
        }
        return staticVersion.strip().equals(runtimeVersion.strip())
                ? "VERSION_MATCH"
                : "VERSION_MISMATCH";
    }

    /** Tài nguyên runtime kèm kết quả nhận diện package. */
    private record EnrichedResource(RuntimeResource resource, PackageIdentification id) {
    }

    public static MatchReport match(
            List<StaticComponent> staticComponents,
            List<RuntimeResource> runtimeResources
    ) {
        // Bổ sung kết quả nhận diện cho từng tài nguyên runtime.
        List<EnrichedResource> enriched = new ArrayList<>();
        for (RuntimeResource resource : runtimeResources) {
            enriched.add(new EnrichedResource(
                    resource, Normalizer.inferPackageFromUrl(resource.url())));
        }

        List<MatchResult> results = new ArrayList<>();
        Set<String> matchedRuntimeIds = new HashSet<>();

        for (StaticComponent component : staticComponents) {
            String staticName = staticPackageName(component);
            String staticVersion = component.version();

            List<EnrichedResource> candidates = new ArrayList<>();
            for (EnrichedResource item : enriched) {
                if (staticName.equals(item.id().packageName())) {
                    candidates.add(item);
                }
            }

            if (candidates.isEmpty()) {
                results.add(new MatchResult(
                        "STATIC_ONLY",
                        component.name(),
                        staticVersion,
                        null,
                        null,
                        "VERSION_UNKNOWN",
                        "Không tìm thấy URL runtime nào được nhận diện là package này bằng quy tắc hiện tại."
                ));
                continue;
            }

            // Nhiều URL cùng package: tổng hợp số lần xuất hiện và khử trùng lặp
            Map<String, Integer> candidateOccurrences = new LinkedHashMap<>();
            Map<String, EnrichedResource> uniqueCandidates = new LinkedHashMap<>();

            for (EnrichedResource item : candidates) {
                matchedRuntimeIds.add(item.resource().resourceId());
                String runtimeVersion = item.id().packageVersion();
                String uniqueKey = (item.resource().url() != null ? item.resource().url() : "")
                        + "::" + (runtimeVersion != null ? runtimeVersion : "");
                
                candidateOccurrences.put(uniqueKey, candidateOccurrences.getOrDefault(uniqueKey, 0) + 1);
                uniqueCandidates.putIfAbsent(uniqueKey, item);
            }

            for (Map.Entry<String, EnrichedResource> entry : uniqueCandidates.entrySet()) {
                EnrichedResource item = entry.getValue();
                int count = candidateOccurrences.getOrDefault(entry.getKey(), 1);

                String runtimeVersion = item.id().packageVersion();
                String versionStatus = compareVersion(staticVersion, runtimeVersion);

                String status;
                String evidence;
                String suffixCount = count > 1 ? " (ghi nhận qua " + count + " yêu cầu mạng)" : "";

                switch (versionStatus) {
                    case "VERSION_MATCH" -> {
                        status = "MATCHED";
                        evidence = "Tên và phiên bản khớp theo thông tin nhận diện từ SBOM và URL runtime" + suffixCount + ".";
                    }
                    case "VERSION_MISMATCH" -> {
                        status = "UNRESOLVED";
                        evidence = "Tên package khớp nhưng phiên bản khác nhau; cần kiểm tra nguồn dữ liệu và phạm vi quét" + suffixCount + ".";
                    }
                    default -> {
                        status = "UNRESOLVED";
                        evidence = "Tên package khớp nhưng chưa đủ thông tin để xác nhận phiên bản" + suffixCount + ".";
                    }
                }

                results.add(new MatchResult(
                        status,
                        component.name(),
                        staticVersion,
                        item.resource().url(),
                        runtimeVersion,
                        versionStatus,
                        evidence
                ));
            }
        }

        // Xử lý các tài nguyên runtime chưa được ghép với SBOM (khử trùng lặp theo URL/Package).
        Set<String> seenUnmatchedKeys = new HashSet<>();
        for (EnrichedResource item : enriched) {
            if (matchedRuntimeIds.contains(item.resource().resourceId())) {
                continue;
            }

            String runtimeName = item.id().packageName();
            String uniqueUnmatchedKey = (runtimeName != null ? runtimeName : "")
                    + "::" + (item.resource().url() != null ? item.resource().url() : "");
            if (seenUnmatchedKeys.contains(uniqueUnmatchedKey)) {
                continue;
            }
            seenUnmatchedKeys.add(uniqueUnmatchedKey);

            String status;
            String evidence;

            if (runtimeName == null) {
                status = "UNRESOLVED";
                evidence = "Tài nguyên runtime chưa được nhận diện thành package. Không thể kết luận nó có phải dependency bị thiếu trong SBOM hay không.";
            } else {
                status = "RUNTIME_ONLY";
                evidence = "Đã nhận diện tên package từ URL nhưng chưa tìm thấy component tương ứng trong SBOM tĩnh.";
            }

            results.add(new MatchResult(
                    status,
                    runtimeName != null ? runtimeName : item.resource().url(),
                    null,
                    item.resource().url(),
                    item.id().packageVersion(),
                    "VERSION_UNKNOWN",
                    evidence
            ));
        }

        Map<String, Integer> statusCounts = new LinkedHashMap<>();
        for (String status : STATUSES) {
            statusCounts.put(status,
                    (int) results.stream().filter(r -> r.status().equals(status)).count());
        }

        MatchReport.Summary summary = new MatchReport.Summary(
                staticComponents.size(),
                runtimeResources.size(),
                results.size(),
                statusCounts
        );

        return new MatchReport(summary, results);
    }
}

