package com.example.sbom;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableScheduling;

/**
 * Application entry point.
 *
 * {@link EnableScheduling} activates {@code @Scheduled} methods like
 * {@code TrivyCacheCleanupService.cleanupOldCacheDirs()}.
 */
@SpringBootApplication
@EnableScheduling
public class SbomApplication {

	public static void main(String[] args) {
		SpringApplication.run(SbomApplication.class, args);
	}

}
