package com.example.sbom.ai.service.validator;

import org.springframework.stereotype.Component;
import org.springframework.web.multipart.MultipartFile;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@Component
public class FileValidator {

    private static final Logger log = LoggerFactory.getLogger(FileValidator.class);
    private static final long MAX_BYTES = 10L * 1024L * 1024L; // 10MB

    public void validateFile(MultipartFile file) {
        if (file == null || file.isEmpty()) {
            throw new IllegalArgumentException("File is empty");
        }

        String filename = file.getOriginalFilename();
        if (filename == null) {
            throw new IllegalArgumentException("File name is null");
        }

        if (!filename.toLowerCase().endsWith(".json")) {
            throw new IllegalArgumentException("Only .json files are allowed");
        }

        if (file.getSize() > MAX_BYTES) {
            throw new IllegalArgumentException("File size exceeds limit (10MB)");
        }

        log.info("File validation passed: {}", filename);
    }
}