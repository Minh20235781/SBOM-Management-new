package com.example.sbom.repository;

import com.example.sbom.entity.VulnStatusHistory;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.Collection;
import java.util.List;
import java.util.Optional;

@Repository
public interface VulnStatusHistoryRepository extends JpaRepository<VulnStatusHistory, Long> {

 /**
 * Lookup a single (vuln, package) row for a project. Used by
 * {@code VulnDiffService} to decide between NEW and STILL_OPEN/REOPENED
 * when a vuln reappears in a new scan.
 */
 @Query("SELECT h FROM VulnStatusHistory h " +
 "WHERE h.projectId = :projectId AND h.vulnId = :vulnId " +
 "AND ((:packagePurl IS NULL AND h.packagePurl IS NULL) OR h.packagePurl = :packagePurl)")
 Optional<VulnStatusHistory> findRow(@Param("projectId") Long projectId,
 @Param("vulnId") String vulnId,
 @Param("packagePurl") String packagePurl);

 List<VulnStatusHistory> findByProjectIdOrderByLastSeenAtDesc(Long projectId);

 List<VulnStatusHistory> findByProjectIdAndStatusOrderByLastSeenAtDesc(Long projectId,
 VulnStatusHistory.Status status);

 long countByProjectIdAndStatus(Long projectId, VulnStatusHistory.Status status);

 /**
 * Count vuln-status rows attached to a specific scan that
 * fall into any of the supplied statuses. Used by the
 * {@code /commits} endpoint to decide whether a commit
 * produced NEW/FIXED/REOPENED state changes after it was
 * scanned — if zero rows changed, the commit was a "no
 * impact" rescan (e.g. CI workflow bumps, source-code
 * refactors) and the UI can skip showing a Re-scan button.
 */
 long countByScanIdAndStatusIn(Long scanId, Collection<VulnStatusHistory.Status> statuses);

 /**
 * Convenience counter: count NEW + FIXED + REOPENED rows
 * attached to a scan. Treats those three statuses as
 * "the scan actually changed something"; STILL_OPEN
 * rows are not counted because every still-open vuln
 * gets a still-open row and they would mask real diffs.
 */
 default long countImpactForScan(Long scanId) {
  if (scanId == null) return 0L;
  return countByScanIdAndStatusIn(scanId,
    java.util.List.of(
     VulnStatusHistory.Status.NEW,
     VulnStatusHistory.Status.FIXED,
     VulnStatusHistory.Status.REOPENED));
 }

 /**
 * Wipe all vuln-status rows for a project. Used by the
 * "Reset project" flow in Settings.
 */
 @org.springframework.data.jpa.repository.Modifying
 @org.springframework.data.jpa.repository.Query(
 "DELETE FROM VulnStatusHistory h WHERE h.projectId = :projectId")
 int deleteByProjectId(@Param("projectId") Long projectId);
}
