package com.example.sbom.service;

import com.example.sbom.entity.VulnStatusHistory;
import com.example.sbom.entity.VulnerabilityEntity;
import com.example.sbom.repository.ProjectRepository;
import com.example.sbom.repository.VulnStatusHistoryRepository;
import com.example.sbom.repository.VulnerabilityRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

import java.time.Instant;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

/**
 * Phase 4: diff the current set of vulnerabilities for a project against
 * the persisted {@link VulnStatusHistory} rows and update them in place.
 *
 * Identity key: {@code (vulnId, packagePurl)} — a single CVE that affects
 * multiple packages in the same project is tracked as multiple rows.
 *
 * Called from {@code RiskAssessmentAspect} immediately after the snapshot
 * row is written. Failures here are best-effort: callers should catch and
 * log, never propagate.
 */
@Service
public class VulnDiffService {

 private static final Logger log = LoggerFactory.getLogger(VulnDiffService.class);

 private final VulnerabilityRepository vulnerabilityRepository;
 private final VulnStatusHistoryRepository historyRepository;
 private final ProjectRepository projectRepository;

 public VulnDiffService(VulnerabilityRepository vulnerabilityRepository,
 VulnStatusHistoryRepository historyRepository,
 ProjectRepository projectRepository) {
 this.vulnerabilityRepository = vulnerabilityRepository;
 this.historyRepository = historyRepository;
 this.projectRepository = projectRepository;
 }

 /** Result of one diff invocation, returned for logging. */
 public record DiffResult(int newCount, int fixedCount, int stillOpenCount, int reopenedCount) {}

 /**
 * Compute the diff for {@code projectId} and persist updated
 * {@link VulnStatusHistory} rows. The {@code scanId} is the id of the
 * {@code RiskAssessment} row that just triggered this diff; it's stored
 * on each row that changes so the audit timeline can join.
 */
 @Transactional
 public DiffResult diff(Long projectId, Long scanId) {
 Objects.requireNonNull(projectId, "projectId");
 if (!projectRepository.existsById(projectId)) {
 throw new ResponseStatusException(HttpStatus.NOT_FOUND,
 "Project not found: id=" + projectId);
 }

 Instant now = Instant.now();

 // 1. Snapshot of the current state of the project's vulnerabilities.
 List<VulnerabilityEntity> current = vulnerabilityRepository.findAll().stream()
 .filter(v -> v.getProjectId() != null && v.getProjectId().equals(projectId))
 .toList();

 Set<VulnKey> currentKeys = new HashSet<>();
 for (VulnerabilityEntity v : current) {
 currentKeys.add(new VulnKey(v.getVulnId(), v.getPkg() == null ? null : v.getPkg().getPurl()));
 }

 // 2. Existing history rows for the project — these represent the
 // "previous scan" because nothing in this method has run yet.
 List<VulnStatusHistory> existing = historyRepository.findByProjectIdOrderByLastSeenAtDesc(projectId);
 Set<VulnKey> existingKeys = new HashSet<>();
 for (VulnStatusHistory h : existing) {
 existingKeys.add(new VulnKey(h.getVulnId(), h.getPackagePurl()));
 }

 int newCount = 0;
 int fixedCount = 0;
 int stillOpenCount = 0;
 int reopenedCount = 0;

 // 3. Process each current vuln.
 for (VulnerabilityEntity v : current) {
 VulnKey key = new VulnKey(v.getVulnId(), v.getPkg() == null ? null : v.getPkg().getPurl());
 Optional<VulnStatusHistory> prior =
 historyRepository.findRow(projectId, key.vulnId, key.packagePurl);

 if (prior.isEmpty()) {
 // Truly new vuln — has never been observed in this project.
 VulnStatusHistory row = new VulnStatusHistory();
 row.setProjectId(projectId);
 row.setVulnId(key.vulnId);
 row.setPackagePurl(key.packagePurl);
 row.setStatus(VulnStatusHistory.Status.NEW);
 row.setSeverity(normalizeSeverity(v.getSeverity()));
 row.setCvssScore(v.getCvssScore());
 row.setFirstSeenAt(now);
 row.setLastSeenAt(now);
 row.setScanId(scanId);
 historyRepository.save(row);
 newCount++;
 } else {
 VulnStatusHistory row = prior.get();
 VulnStatusHistory.Status prev = row.getStatus();
 if (prev == VulnStatusHistory.Status.FIXED) {
 // Re-introduced after being resolved.
 row.setStatus(VulnStatusHistory.Status.REOPENED);
 row.setResolvedAt(null);
 row.setSeverity(normalizeSeverity(v.getSeverity()));
 row.setCvssScore(v.getCvssScore());
 row.setLastSeenAt(now);
 row.setScanId(scanId);
 historyRepository.save(row);
 reopenedCount++;
 } else {
 // Still present — bump lastSeenAt and refresh severity/score.
 row.setStatus(VulnStatusHistory.Status.STILL_OPEN);
 row.setSeverity(normalizeSeverity(v.getSeverity()));
 row.setCvssScore(v.getCvssScore());
 row.setLastSeenAt(now);
 row.setScanId(scanId);
 historyRepository.save(row);
 stillOpenCount++;
 }
 }
 }

 // 4. Anything in the previous set that wasn't in the current set is FIXED.
 // We only count rows whose status was open before; rows that were already
 // FIXED stay FIXED (they're not in the current set by definition).
 for (VulnStatusHistory h : existing) {
 VulnKey key = new VulnKey(h.getVulnId(), h.getPackagePurl());
 if (currentKeys.contains(key)) continue;
 if (h.getStatus() == VulnStatusHistory.Status.FIXED) continue; // already counted
 h.setStatus(VulnStatusHistory.Status.FIXED);
 h.setResolvedAt(now);
 h.setLastSeenAt(now);
 h.setScanId(scanId);
 historyRepository.save(h);
 fixedCount++;
 }

 log.info("VulnDiffService: projectId={} scanId={} new={} fixed={} stillOpen={} reopened={}",
 projectId, scanId, newCount, fixedCount, stillOpenCount, reopenedCount);
 return new DiffResult(newCount, fixedCount, stillOpenCount, reopenedCount);
 }

 @Transactional(readOnly = true)
 public List<VulnStatusHistory> getHistory(Long projectId, String statusFilter, int limit) {
 Objects.requireNonNull(projectId, "projectId");
 if (!projectRepository.existsById(projectId)) {
 throw new ResponseStatusException(HttpStatus.NOT_FOUND,
 "Project not found: id=" + projectId);
 }
 List<VulnStatusHistory> rows;
 if (statusFilter == null || statusFilter.isBlank()) {
 rows = historyRepository.findByProjectIdOrderByLastSeenAtDesc(projectId);
 } else {
 VulnStatusHistory.Status s;
 try {
 s = VulnStatusHistory.Status.valueOf(statusFilter.toUpperCase(Locale.ROOT));
 } catch (IllegalArgumentException e) {
 throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
 "Unknown status: " + statusFilter);
 }
 rows = historyRepository.findByProjectIdAndStatusOrderByLastSeenAtDesc(projectId, s);
 }
 if (limit > 0 && rows.size() > limit) {
 return rows.subList(0, limit);
 }
 return rows;
 }

 @Transactional(readOnly = true)
 public Stats stats(Long projectId) {
 Objects.requireNonNull(projectId, "projectId");
 if (!projectRepository.existsById(projectId)) {
 throw new ResponseStatusException(HttpStatus.NOT_FOUND,
 "Project not found: id=" + projectId);
 }
 long newC = historyRepository.countByProjectIdAndStatus(projectId, VulnStatusHistory.Status.NEW);
 long openC = historyRepository.countByProjectIdAndStatus(projectId, VulnStatusHistory.Status.STILL_OPEN);
 long fixedC = historyRepository.countByProjectIdAndStatus(projectId, VulnStatusHistory.Status.FIXED);
 long reopenedC = historyRepository.countByProjectIdAndStatus(projectId, VulnStatusHistory.Status.REOPENED);
 return new Stats(newC, openC, fixedC, reopenedC);
 }

 public record Stats(long newCount, long stillOpenCount, long fixedCount, long reopenedCount) {}

 /** Composite identity used to match a vulnerability across scans. */
 private record VulnKey(String vulnId, String packagePurl) {
 VulnKey {
 // vulnId is the only required field; packagePurl may be null when the
 // upload didn't carry a purl for the affected component.
 Objects.requireNonNull(vulnId, "vulnId");
 }
 }

 private static String normalizeSeverity(String s) {
 return s == null ? null : s.toUpperCase(Locale.ROOT);
 }
}
