package com.example.sbom.service.scan;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.stream.Stream;

/**
 * Periodically prunes old UUID-keyed Trivy cache dirs.
 *
 * <p>Every {@link TrivyScanService#scanRepo(String)} / {@code scanLocalRepository}
 * invocation creates a fresh cache subdir under {@code trivy.cache-dir}, named
 * {@code scan_<UUID>}. Without cleanup, these accumulate and eventually fill
 * the disk — after which Trivy starts failing for new repos. The 12-hourly
 * cleanup deletes any cache subdir older than
 * {@code trivy.cache.cleanup.retention-hours} (default 24h, so a recently
 * scanned repo still benefits from a warm cache).
 *
 * <p>The shared Trivy DB caches ({@code db/}, {@code java-db/}) live directly
 * under the cache root and are NOT touched — they must persist across scans
 * to avoid re-downloading the vulnerability database.
 */
@Service
public class TrivyCacheCleanupService {

    private static final Logger log = LoggerFactory.getLogger(TrivyCacheCleanupService.class);

    @Value("${trivy.cache-dir:F:/trivy-cache}")
    private String cacheDirRoot;

    @Value("${trivy.cache.cleanup.retention-hours:24}")
    private int retentionHours;

    @Value("${trivy.cache.cleanup.enabled:true}")
    private boolean enabled;

    /**
     * Default cron: every 12 hours at hh:00:00 (00:00 and 12:00).
     * Override via {@code trivy.cache.cleanup.cron} in application.properties.
     */
    @Scheduled(cron = "${trivy.cache.cleanup.cron:0 0 0/12 * * *}")
    public void cleanupOldCacheDirs() {
        if (!enabled) {
            log.debug("Trivy cache cleanup is disabled");
            return;
        }
        File root = new File(cacheDirRoot);
        if (!root.isDirectory()) {
            log.warn("Trivy cache root does not exist: {}", root.getAbsolutePath());
            return;
        }
        long cutoffMs = System.currentTimeMillis() - (long) retentionHours * 3_600_000L;
        File[] children = root.listFiles();
        if (children == null) {
            log.warn("Trivy cache root is not readable: {}", root.getAbsolutePath());
            return;
        }

        int deleted = 0;
        long bytesFreed = 0;
        for (File child : children) {
            if (!child.isDirectory()) continue;
            if (!child.getName().startsWith("scan_")) continue;
            if (child.lastModified() >= cutoffMs) continue;

            long sizeBefore = dirSize(child);
            try {
                deleteRecursively(child);
                deleted++;
                bytesFreed += sizeBefore;
                log.info("Trivy cache cleanup: removed {} ({} MB)",
                        child.getName(), sizeBefore / 1_048_576L);
            } catch (IOException ex) {
                log.warn("Trivy cache cleanup: failed to remove {}: {}",
                        child.getAbsolutePath(), ex.getMessage());
            }
        }
        log.info("Trivy cache cleanup done: deleted={}, freed={} MB (retention={}h)",
                deleted, bytesFreed / 1_048_576L, retentionHours);
    }

    private static long dirSize(File dir) {
        try (Stream<Path> walk = Files.walk(dir.toPath())) {
            return walk
                    .filter(Files::isRegularFile)
                    .mapToLong(p -> {
                        try {
                            return Files.size(p);
                        } catch (IOException e) {
                            return 0L;
                        }
                    })
                    .sum();
        } catch (IOException e) {
            return 0L;
        }
    }

    private static void deleteRecursively(File file) throws IOException {
        if (file.isDirectory()) {
            File[] entries = file.listFiles();
            if (entries != null) {
                for (File entry : entries) {
                    deleteRecursively(entry);
                }
            }
        }
        Files.deleteIfExists(file.toPath());
    }
}