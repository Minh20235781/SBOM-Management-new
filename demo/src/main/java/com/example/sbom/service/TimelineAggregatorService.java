package com.example.sbom.service;

import com.example.sbom.dto.AuditEventDTO;
import com.example.sbom.entity.ModuleHistory;
import com.example.sbom.entity.ProjectHistory;
import com.example.sbom.entity.RepoConfigHistory;
import com.example.sbom.entity.RiskAssessment;
import com.example.sbom.entity.SbomFileHistory;
import com.example.sbom.entity.VulnStatusHistory;
import com.example.sbom.repository.ModuleHistoryRepository;
import com.example.sbom.repository.ProjectHistoryRepository;
import com.example.sbom.repository.ProjectRepository;
import com.example.sbom.repository.RepoConfigHistoryRepository;
import com.example.sbom.repository.RiskAssessmentRepository;
import com.example.sbom.repository.SbomFileHistoryRepository;
import com.example.sbom.repository.VulnStatusHistoryRepository;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * Phase 5: aggregate audit events for a single project from six sources:
 *
 * <ol>
 * <li>{@code project_history} — project create/update/delete</li>
 * <li>{@code module_history} — module create/update/delete</li>
 * <li>{@code repo_config_history} — repo config create/update/delete</li>
 * <li>{@code sbom_file_history} — sbom uploads and scan state changes</li>
 * <li>{@code risk_assessment} — every scan's score/grade</li>
 * <li>{@code vuln_status_history} — NEW/FIXED/REOPENED only (STILL_OPEN is filtered out to keep the timeline readable)</li>
 * </ol>
 *
 * Events are merged in memory and sorted DESC by timestamp. Filtering
 * happens after merge so callers get consistent ordering regardless of
 * which sources matched.
 */
@Service
public class TimelineAggregatorService {

 private static final Logger log = LoggerFactory.getLogger(TimelineAggregatorService.class);

 private static final int DEFAULT_LIMIT = 100;
 private static final int MAX_LIMIT = 500;
 private static final Set<VulnStatusHistory.Status> INTERESTING_VULN_STATUSES =
 Set.of(VulnStatusHistory.Status.NEW, VulnStatusHistory.Status.FIXED, VulnStatusHistory.Status.REOPENED);

 private final ProjectRepository projectRepository;
 private final ProjectHistoryRepository projectHistoryRepository;
 private final ModuleHistoryRepository moduleHistoryRepository;
 private final RepoConfigHistoryRepository repoConfigHistoryRepository;
 private final SbomFileHistoryRepository sbomFileHistoryRepository;
 private final RiskAssessmentRepository riskAssessmentRepository;
 private final VulnStatusHistoryRepository vulnStatusHistoryRepository;
 private final ObjectMapper objectMapper;

 public TimelineAggregatorService(ProjectRepository projectRepository,
 ProjectHistoryRepository projectHistoryRepository,
 ModuleHistoryRepository moduleHistoryRepository,
 RepoConfigHistoryRepository repoConfigHistoryRepository,
 SbomFileHistoryRepository sbomFileHistoryRepository,
 RiskAssessmentRepository riskAssessmentRepository,
 VulnStatusHistoryRepository vulnStatusHistoryRepository,
 ObjectMapper objectMapper) {
 this.projectRepository = projectRepository;
 this.projectHistoryRepository = projectHistoryRepository;
 this.moduleHistoryRepository = moduleHistoryRepository;
 this.repoConfigHistoryRepository = repoConfigHistoryRepository;
 this.sbomFileHistoryRepository = sbomFileHistoryRepository;
 this.riskAssessmentRepository = riskAssessmentRepository;
 this.vulnStatusHistoryRepository = vulnStatusHistoryRepository;
 this.objectMapper = objectMapper;
 }

 @Transactional(readOnly = true)
 public List<AuditEventDTO> getTimeline(Long projectId,
 AuditEventDTO.Type typeFilter,
 Instant from,
 Instant to,
 Integer limit) {
 Objects.requireNonNull(projectId, "projectId");
 if (!projectRepository.existsById(projectId)) {
 throw new ResponseStatusException(HttpStatus.NOT_FOUND,
 "Project not found: id=" + projectId);
 }

 int effectiveLimit = (limit == null || limit <= 0) ? DEFAULT_LIMIT : Math.min(limit, MAX_LIMIT);

 List<AuditEventDTO> events = new ArrayList<>();
 events.addAll(toProjectEvents(projectHistoryRepository.findByProjectIdOrderByChangedAtDesc(projectId)));
 events.addAll(toModuleEvents(moduleHistoryRepository.findByProjectIdOrderByChangedAtDesc(projectId)));
 events.addAll(toRepoConfigEvents(repoConfigHistoryRepository.findByProjectIdOrderByChangedAtDesc(projectId)));
 events.addAll(toSbomFileEvents(sbomFileHistoryRepository.findByProjectIdOrderByChangedAtDesc(projectId)));
 events.addAll(toRiskAssessmentEvents(riskAssessmentRepository.findByProjectIdOrderByAssessedAtDesc(projectId)));
 events.addAll(toVulnEvents(vulnStatusHistoryRepository.findByProjectIdOrderByLastSeenAtDesc(projectId)));

 // Apply filters in-memory.
 List<AuditEventDTO> filtered = new ArrayList<>();
 for (AuditEventDTO e : events) {
 if (typeFilter != null && e.getType() != typeFilter) continue;
 if (from != null && e.getTimestamp().isBefore(from)) continue;
 if (to != null && e.getTimestamp().isAfter(to)) continue;
 filtered.add(e);
 }

 filtered.sort(Comparator.comparing(AuditEventDTO::getTimestamp,
 Comparator.nullsLast(Comparator.reverseOrder())));

 if (filtered.size() > effectiveLimit) {
 return filtered.subList(0, effectiveLimit);
 }
 return filtered;
 }

 // ---- mapping helpers ----

 private List<AuditEventDTO> toProjectEvents(List<ProjectHistory> rows) {
 List<AuditEventDTO> out = new ArrayList<>(rows.size());
 for (ProjectHistory h : rows) {
 AuditEventDTO e = new AuditEventDTO();
 e.setTimestamp(h.getChangedAt());
 e.setType(AuditEventDTO.Type.PROJECT);
 e.setAction(h.getChangeType() == null ? "UNKNOWN" : h.getChangeType().name());
 e.setEntityId(String.valueOf(h.getId()));
 e.setEntityName(null);
 e.setSummary(buildProjectSummary(h));
 e.setDetails(parseJsonSafe(h.getSnapshotJson()));
 out.add(e);
 }
 return out;
 }

 private List<AuditEventDTO> toModuleEvents(List<ModuleHistory> rows) {
 List<AuditEventDTO> out = new ArrayList<>(rows.size());
 for (ModuleHistory h : rows) {
 AuditEventDTO e = new AuditEventDTO();
 e.setTimestamp(h.getChangedAt());
 e.setType(AuditEventDTO.Type.MODULE);
 e.setAction(h.getChangeType() == null ? "UNKNOWN" : h.getChangeType().name());
 e.setEntityId(String.valueOf(h.getId()));
 e.setEntityName(null);
 Map<String, Object> details = parseJsonSafe(h.getSnapshotJson());
 e.setSummary("Module " + (h.getChangeType() == null ? "changed" : h.getChangeType().name().toLowerCase())
 + (details != null && details.get("name") != null ? ": " + details.get("name") : ""));
 e.setDetails(details);
 out.add(e);
 }
 return out;
 }

 private List<AuditEventDTO> toRepoConfigEvents(List<RepoConfigHistory> rows) {
 List<AuditEventDTO> out = new ArrayList<>(rows.size());
 for (RepoConfigHistory h : rows) {
 AuditEventDTO e = new AuditEventDTO();
 e.setTimestamp(h.getChangedAt());
 e.setType(AuditEventDTO.Type.REPO_CONFIG);
 e.setAction(h.getChangeType() == null ? "UNKNOWN" : h.getChangeType().name());
 e.setEntityId(String.valueOf(h.getId()));
 Map<String, Object> details = parseJsonSafe(h.getSnapshotJson());
 String repoUrl = details == null ? null : (String) details.get("repoUrl");
 e.setEntityName(repoUrl);
 e.setSummary("Repo config " + (h.getChangeType() == null ? "changed" : h.getChangeType().name().toLowerCase())
 + (repoUrl == null ? "" : ": " + repoUrl));
 e.setDetails(details);
 out.add(e);
 }
 return out;
 }

 private List<AuditEventDTO> toSbomFileEvents(List<SbomFileHistory> rows) {
 List<AuditEventDTO> out = new ArrayList<>(rows.size());
 for (SbomFileHistory h : rows) {
 AuditEventDTO e = new AuditEventDTO();
 e.setTimestamp(h.getChangedAt());
 e.setType(AuditEventDTO.Type.SBOM_FILE);
 e.setAction(h.getChangeType() == null ? "UNKNOWN" : h.getChangeType().name());
 e.setEntityId(String.valueOf(h.getId()));
 String name = h.getSnapshotJson() == null ? null : extractFileName(h.getSnapshotJson());
 e.setEntityName(name);
 e.setSummary("SBOM file " + (h.getChangeType() == null ? "changed" : h.getChangeType().name().toLowerCase())
 + (name == null ? "" : ": " + name));
 e.setDetails(parseJsonSafe(h.getSnapshotJson()));
 out.add(e);
 }
 return out;
 }

 private List<AuditEventDTO> toRiskAssessmentEvents(List<RiskAssessment> rows) {
 List<AuditEventDTO> out = new ArrayList<>(rows.size());
 for (RiskAssessment ra : rows) {
 AuditEventDTO e = new AuditEventDTO();
 e.setTimestamp(ra.getAssessedAt());
 e.setType(AuditEventDTO.Type.RISK_ASSESSMENT);
 e.setAction("SCORED");
 e.setEntityId(String.valueOf(ra.getId()));
 e.setEntityName("Score " + round1(ra.getScore()) + " (" + ra.getGrade() + ")");
 e.setSummary(String.format("Scan scored %s (%s) with %d vulnerabilities",
 round1(ra.getScore()), ra.getGrade(), ra.getTotalVulnerabilities()));
 Map<String, Object> details = new HashMap<>();
 details.put("score", ra.getScore());
 details.put("grade", ra.getGrade());
 details.put("totalPackages", ra.getTotalPackages());
 details.put("totalVulnerabilities", ra.getTotalVulnerabilities());
 details.put("criticalCount", ra.getCriticalCount());
 details.put("highCount", ra.getHighCount());
 details.put("mediumCount", ra.getMediumCount());
 details.put("lowCount", ra.getLowCount());
 details.put("moduleId", ra.getModuleId());
 details.put("sbomFileId", ra.getSbomFileId());
 e.setDetails(details);
 out.add(e);
 }
 return out;
 }

 private List<AuditEventDTO> toVulnEvents(List<VulnStatusHistory> rows) {
 List<AuditEventDTO> out = new ArrayList<>(rows.size());
 for (VulnStatusHistory h : rows) {
 if (!INTERESTING_VULN_STATUSES.contains(h.getStatus())) continue; // skip STILL_OPEN noise
 AuditEventDTO e = new AuditEventDTO();
 e.setTimestamp(h.getLastSeenAt());
 e.setType(AuditEventDTO.Type.VULN);
 e.setAction(h.getStatus() == null ? "UNKNOWN" : h.getStatus().name());
 e.setEntityId(h.getVulnId());
 e.setEntityName(h.getVulnId());
 e.setSummary(buildVulnSummary(h));
 Map<String, Object> details = new HashMap<>();
 details.put("vulnId", h.getVulnId());
 details.put("packagePurl", h.getPackagePurl());
 details.put("severity", h.getSeverity());
 details.put("cvssScore", h.getCvssScore());
 details.put("firstSeenAt", h.getFirstSeenAt());
 details.put("lastSeenAt", h.getLastSeenAt());
 details.put("resolvedAt", h.getResolvedAt());
 details.put("fixedInVersion", h.getFixedInVersion());
 details.put("scanId", h.getScanId());
 e.setDetails(details);
 out.add(e);
 }
 return out;
 }

 private String buildProjectSummary(ProjectHistory h) {
 Map<String, Object> details = parseJsonSafe(h.getSnapshotJson());
 String name = details == null ? null : (String) details.get("name");
 String action = h.getChangeType() == null ? "changed" : h.getChangeType().name().toLowerCase();
 return "Project " + action + (name == null ? "" : ": " + name);
 }

 private String buildVulnSummary(VulnStatusHistory h) {
 String pkg = h.getPackagePurl() == null ? "" : " in " + h.getPackagePurl();
 String status = h.getStatus() == null ? "changed" : h.getStatus().name().toLowerCase();
 return String.format("Vulnerability %s %s%s", h.getVulnId(), status, pkg);
 }

 private Map<String, Object> parseJsonSafe(String json) {
 if (json == null || json.isBlank()) return null;
 try {
 return objectMapper.readValue(json, new TypeReference<Map<String, Object>>() {});
 } catch (Exception ex) {
 log.debug("TimelineAggregatorService: failed to parse snapshot JSON, returning raw string");
 Map<String, Object> wrapped = new HashMap<>();
 wrapped.put("raw", json);
 return wrapped;
 }
 }

 private String extractFileName(String json) {
 Map<String, Object> m = parseJsonSafe(json);
 if (m == null) return null;
 Object name = m.get("fileName");
 return name == null ? null : name.toString();
 }

 private static String round1(Double v) {
 if (v == null) return "?";
 return String.format("%.1f", v);
 }
}
