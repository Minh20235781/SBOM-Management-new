package com.example.sbom.service;

import com.example.sbom.dto.RiskyPackageDTO;
import com.example.sbom.entity.PackageEntity;
import com.example.sbom.repository.PackageRepository;
import org.springframework.stereotype.Service;

import java.util.*;

@Service
public class AnomalyService {

    private final PackageRepository packageRepo;

    public AnomalyService(PackageRepository packageRepo) {
        this.packageRepo = packageRepo;
    }


    public List<RiskyPackageDTO> getTopVulnerablePackages(int topN, String repoName) {
        return computeAnomalies(repoName).stream()
                .filter(dto -> dto.getVulnCount() > 0)
                .sorted(Comparator.comparingDouble(RiskyPackageDTO::getVulnAnomaly).reversed())
                .limit(topN)
                .toList();
    }

    public List<RiskyPackageDTO> getTopHubPackages(int topN, String repoName) {
        return computeAnomalies(repoName).stream()
                .sorted(Comparator.comparingDouble(RiskyPackageDTO::getHubAnomaly).reversed())
                .limit(topN)
                .toList();
    }

    public List<RiskyPackageDTO> getTopRiskyPackages(int topN, String repoName) {
        List<RiskyPackageDTO> allPackages = computeAnomalies(repoName);

        // In debug thông tin
        System.out.println("=== DEBUG INFO ===");
        System.out.println("Total packages: " + allPackages.size());
        System.out.println("Packages with vuln: " +
                allPackages.stream().filter(d -> d.getVulnCount() > 0).count());
        System.out.println("Packages without vuln: " +
                allPackages.stream().filter(d -> d.getVulnCount() == 0).count());

        return allPackages.stream()
                .sorted((a, b) -> {
                    if (a.getVulnCount() > 0 && b.getVulnCount() == 0) return -1;
                    if (a.getVulnCount() == 0 && b.getVulnCount() > 0) return 1;

                    double scoreA = a.getVulnAnomaly() * 0.7 + a.getHubAnomaly() * 0.3;
                    double scoreB = b.getVulnAnomaly() * 0.7 + b.getHubAnomaly() * 0.3;
                    return Double.compare(scoreB, scoreA);
                })
                .limit(topN)
                .toList();
    }

    /* =====================================================
        Core anomaly computation
       ===================================================== */

    private List<RiskyPackageDTO> computeAnomalies(String repoName) {

        // Normalize repoName: accept either plain repo name or full URL
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
                ? packageRepo.findAllWithVulnerabilities()
                : packageRepo.findAllByRepoWithVulnerabilities(repoName);

        if (packages.isEmpty()) {
            return Collections.emptyList();
        }

        // Consolidate packages by name and pick the latest version per package
        Map<String, PackageEntity> latestByName = new HashMap<>();
        for (PackageEntity pkg : packages) {
            String name = pkg.getName();
            if (!latestByName.containsKey(name)) {
                latestByName.put(name, pkg);
            } else {
                PackageEntity existing = latestByName.get(name);
                if (compareVersions(pkg.getVersion(), existing.getVersion()) > 0) {
                    latestByName.put(name, pkg);
                }
            }
        }

        List<RiskyPackageDTO> list = new ArrayList<>();

        // Phase 1: Collect data from latest versions only
        for (PackageEntity pkg : latestByName.values()) {

            int vulnCount = pkg.getVulnerabilities().size();

            int highSeverity = (int) pkg.getVulnerabilities().stream()
                    .filter(v -> {
                        String sev = v.getSeverity();
                        return "high".equalsIgnoreCase(sev) || "critical".equalsIgnoreCase(sev);
                    })
                    .count();

            double cvssMax = pkg.getVulnerabilities().stream()
                    .mapToDouble(v -> v.getCvssScore() != null ? v.getCvssScore() : 0.0)
                    .max()
                    .orElse(0.0);

            double rankScore = Optional.ofNullable(pkg.getRankScore()).orElse(0.0);
            int dependencyDepth = pkg.getDependencyDepth();
            int repoCount = pkg.getRepoCount();

            boolean orphan =
                    dependencyDepth > 0 &&
                            repoCount <= 1 &&
                            vulnCount == 0;

            RiskyPackageDTO dto = new RiskyPackageDTO(
                    pkg.getName(),
                    pkg.getVersion(),
                    vulnCount,
                    highSeverity,
                    cvssMax,
                    rankScore,
                    repoCount,
                    dependencyDepth,
                    0.0,
                    0.0,
                    orphan
            );

            list.add(dto);
        }

        // Debug giữ nguyên
        System.out.println("\n=== PACKAGE STATS ===");
        System.out.println("Total packages processed: " + list.size());
        System.out.println("Packages with vulnerabilities: " +
                list.stream().filter(d -> d.getVulnCount() > 0).count());

        Map<String, Double> median = new HashMap<>();
        Map<String, Double> mad = new HashMap<>();

        median.put("vuln", median(list.stream().mapToDouble(RiskyPackageDTO::getVulnCount).toArray()));
        median.put("high", median(list.stream().mapToDouble(RiskyPackageDTO::getHighSeverity).toArray()));
        median.put("cvss", median(list.stream().mapToDouble(RiskyPackageDTO::getCvssMax).toArray()));
        median.put("rank", median(list.stream().mapToDouble(RiskyPackageDTO::getRankScore).toArray()));
        median.put("depth", median(list.stream().mapToDouble(RiskyPackageDTO::getDependencyDepth).toArray()));
        median.put("repo", median(list.stream().mapToDouble(RiskyPackageDTO::getRepoCount).toArray()));

        mad.put("vuln", calculateMad(list.stream().mapToDouble(RiskyPackageDTO::getVulnCount).toArray(), median.get("vuln")));
        mad.put("high", calculateMad(list.stream().mapToDouble(RiskyPackageDTO::getHighSeverity).toArray(), median.get("high")));
        mad.put("cvss", calculateMad(list.stream().mapToDouble(RiskyPackageDTO::getCvssMax).toArray(), median.get("cvss")));
        mad.put("rank", calculateMad(list.stream().mapToDouble(RiskyPackageDTO::getRankScore).toArray(), median.get("rank")));
        mad.put("depth", calculateMad(list.stream().mapToDouble(RiskyPackageDTO::getDependencyDepth).toArray(), median.get("depth")));
        mad.put("repo", calculateMad(list.stream().mapToDouble(RiskyPackageDTO::getRepoCount).toArray(), median.get("repo")));

        for (RiskyPackageDTO dto : list) {

            double zVuln  = calculateRobustZ(dto.getVulnCount(), median.get("vuln"), mad.get("vuln"));
            double zHigh  = calculateRobustZ(dto.getHighSeverity(), median.get("high"), mad.get("high"));
            double zCvss  = calculateRobustZ(dto.getCvssMax(), median.get("cvss"), mad.get("cvss"));
            double zRank  = calculateRobustZ(dto.getRankScore(), median.get("rank"), mad.get("rank"));
            double zDepth = calculateRobustZ(dto.getDependencyDepth(), median.get("depth"), mad.get("depth"));
            double zRepo  = calculateRobustZ(dto.getRepoCount(), median.get("repo"), mad.get("repo"));

            double vulnScore;
            if (dto.getVulnCount() == 0) {
                vulnScore = -4.0;
            } else {
                zVuln = capZScore(zVuln);
                zHigh = capZScore(zHigh);
                zCvss = capZScore(zCvss);
                vulnScore = 0.45 * zVuln + 0.35 * zHigh + 0.20 * zCvss;
            }

            double hubScore;
            zRank = capZScore(zRank);
            zDepth = capZScore(zDepth);
            zRepo = capZScore(zRepo);

            if (dto.isOrphan()) {
                hubScore = 0.50 * zRank + 0.10 * zDepth + 0.40 * zRepo;
            } else {
                hubScore = 0.60 * zRank + 0.25 * zDepth + 0.15 * zRepo;
            }

            dto.setVulnAnomaly(sigmoid(vulnScore));
            dto.setHubAnomaly(sigmoid(hubScore));
        }

        return list;
    }

    /* =====================================================
       Math helpers
       ===================================================== */

    private double calculateRobustZ(double value, double median, double mad) {
        if (Math.abs(mad) < 1e-10) return 0.0;
        return (value - median) / mad;
    }

    private double capZScore(double z) {
        if (z > 5) return 5;
        if (z < -5) return -5;
        return z;
    }

    private double median(double[] values) {
        if (values.length == 0) return 0.0;
        double[] sorted = values.clone();
        Arrays.sort(sorted);
        int n = sorted.length;
        if (n % 2 == 0) {
            return (sorted[n / 2 - 1] + sorted[n / 2]) / 2.0;
        } else {
            return sorted[n / 2];
        }
    }

    private double calculateMad(double[] values, double median) {
        if (values.length == 0) return 1.0;
        double[] deviations = Arrays.stream(values)
                .map(v -> Math.abs(v - median))
                .toArray();
        double madValue = median(deviations);
        double minMad = Math.max(median * 0.01, 0.1);
        return Math.max(madValue, minMad);
    }

    private double sigmoid(double x) {
        if (x > 10) return 1.0;
        if (x < -10) return 0.0;
        return 1.0 / (1.0 + Math.exp(-x));
    }

    private int compareVersions(String v1, String v2) {
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

    private int parseLeadingInt(String s) {
        if (s == null) return 0;
        String num = s.replaceAll("\\D", "");
        if (num.isEmpty()) return 0;
        try {
            return Integer.parseInt(num);
        } catch (NumberFormatException ex) {
            return 0;
        }
    }

    public Map<String, Object> getPackageStats(String repoName) {

        List<PackageEntity> packages = (repoName == null || repoName.isEmpty())
                ? packageRepo.findAllWithVulnerabilities()
                : packageRepo.findAllByRepoWithVulnerabilities(repoName);

        Map<String, Object> stats = new HashMap<>();
        stats.put("totalPackages", packages.size());

        List<String> packagesWithVuln = new ArrayList<>();
        List<String> packagesWithoutVuln = new ArrayList<>();

        for (PackageEntity pkg : packages) {
            if (pkg.getVulnerabilities().size() > 0) {
                packagesWithVuln.add(pkg.getName() + " (" + pkg.getVulnerabilities().size() + " vulns)");
            } else {
                packagesWithoutVuln.add(pkg.getName());
            }
        }

        stats.put("packagesWithVuln", packagesWithVuln);
        stats.put("packagesWithoutVuln", packagesWithoutVuln);
        stats.put("countWithVuln", packagesWithVuln.size());
        stats.put("countWithoutVuln", packagesWithoutVuln.size());

        return stats;
    }

    /* =====================================================
   Public API cho package detail
   ===================================================== */
    public Optional<RiskyPackageDTO> getAnomalyOfPackage(String packageName, String repoName) {
        return computeAnomalies(repoName).stream()
                .filter(r -> r.getPackageName().equals(packageName))
                .findFirst();
    }
}
