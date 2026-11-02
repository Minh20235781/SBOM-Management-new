package com.example.sbom.service.persistence;

import com.example.sbom.entity.PackageEntity;
import com.example.sbom.entity.Project;
import com.example.sbom.entity.VulnerabilityEntity;
import com.example.sbom.repository.PackageRepository;
import com.example.sbom.repository.VulnerabilityRepository;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

@Service
@RequiredArgsConstructor
public class SbomPersistenceService {
 private static final Logger log = LoggerFactory.getLogger(SbomPersistenceService.class);

 private final PackageRepository packageRepository;
 private final VulnerabilityRepository vulnerabilityRepository;
 private final ObjectMapper objectMapper = new ObjectMapper();

 /**
 * Backwards-compatible entry point used by older callers and
 * unit tests. Delegates to the project-aware overload with a
 * null project, which behaves the same as before: the package
 * row is created without a project link, and
 * VulnProjectAssigner patches it on next startup.
 */
 @Transactional
 public void saveSbomWithVulns(File sbomFile, String repoName) throws IOException {
 saveSbomWithVulns(sbomFile, repoName, null);
 }

 /**
 * Project-aware overload: also links the created package rows
 * to the given Project so they show up in
 * {@code GET /api/projects/{id}} and the dashboard count. If
 * {@code project} is null, behaves like the legacy method.
 */
 @Transactional
 public void saveSbomWithVulns(File sbomFile, String repoName, Project project) throws IOException {
 JsonNode root = objectMapper.readTree(sbomFile);
 persist(root, repoName, project);
 }

 private void persist(JsonNode root, String repoName, Project project) {
 JsonNode components = root.get("components");
 if (components != null && components.isArray()) {
 for (JsonNode c : components) {
 String purl = c.path("purl").asText(null);
 if (purl == null) continue;

 PackageEntity pkg = packageRepository.findByPurl(purl)
 .orElseGet(() -> {
 PackageEntity newPkg = new PackageEntity();
 newPkg.setName(c.path("name").asText(purl));
 newPkg.setVersion(c.path("version").asText(null));
 newPkg.setPurl(purl);
 newPkg.setType(c.path("type").asText(null));
 newPkg.setRankScore(0.0);
 newPkg.setRepoName(repoName);
 // Project link: only set on first insert. Later
 // updates preserve the original link so the row
 // doesn't jump between projects.
 if (project != null) {
 newPkg.setProject(project);
 }
 return packageRepository.save(newPkg);
 });

 boolean updated = false;
 if (!purl.equals(pkg.getPurl())) { pkg.setPurl(purl); updated = true; }
 String version = c.path("version").asText(null);
 if (version != null && !version.equals(pkg.getVersion())) { pkg.setVersion(version); updated = true; }
 String name = c.path("name").asText(null);
 if (name != null && !name.equals(pkg.getName())) { pkg.setName(name); updated = true; }
 String type = c.path("type").asText(null);
 if (type != null && !type.equals(pkg.getType())) { pkg.setType(type); updated = true; }
 if (!repoName.equals(pkg.getRepoName())) { pkg.setRepoName(repoName); updated = true; }
 if (updated) packageRepository.save(pkg);
 }
 }

 JsonNode vulnsNode = root.get("vulnerabilities");
 if (vulnsNode != null && vulnsNode.isArray()) {
 List<VulnerabilityEntity> batch = new ArrayList<>();
 for (JsonNode v : vulnsNode) {
 JsonNode affects = v.path("affects");
 if (affects != null && affects.isArray()) {
 for (JsonNode aff : affects) {
 String ref = aff.path("ref").asText(null);
 PackageEntity pkg = packageRepository.findByPurl(ref).orElse(null);
 if (pkg != null) {
 VulnerabilityEntity ve = new VulnerabilityEntity();
 ve.setPkg(pkg);
 // Denormalize projectId onto the vuln row.
 // Prefer the package's own project (covers legacy
 // rows); fall back to the scan-time project.
 if (pkg.getProject() != null) {
 ve.setProjectId(pkg.getProject().getId());
 } else if (project != null) {
 ve.setProjectId(project.getId());
 }
 vul_node(batch, v, ve);
 }
 }
 }
 }
 vulnerabilityRepository.saveAll(batch);
 }
 }

 private void vul_node(List<VulnerabilityEntity> batch, JsonNode v, VulnerabilityEntity ve) {
 ve.setVulnId(v.path("id").asText(null));
 JsonNode ratings = v.path("ratings");
 if (ratings != null && ratings.isArray() && !ratings.isEmpty()) {
 String severity = ratings.get(0).path("severity").asText(null);
 double score = ratings.get(0).path("score").asDouble(0.0);
 if (score <= 0.0 && severity != null) {
 score = switch (severity.toUpperCase(java.util.Locale.ROOT)) {
 case "CRITICAL" -> 9.5;
 case "HIGH" -> 7.8;
 case "MEDIUM" -> 5.5;
 case "LOW" -> 2.5;
 default -> 0.0;
 };
 }
 ve.setSeverity(severity);
 ve.setCvssScore(score);
 }
 ve.setDescription(v.path("description").asText(null));
 JsonNode advisories = v.path("advisories");
 if (advisories != null && advisories.isArray() && !advisories.isEmpty()) {
 ve.setUrl(advisories.get(0).path("url").asText(null));
 }
 batch.add(ve);
 }

 private int getSavedVuln(int savedVuln, List<VulnerabilityEntity> batch, JsonNode v, VulnerabilityEntity ve) {
 vul_node(batch, v, ve);
 savedVuln++;
 return savedVuln;
 }
}
