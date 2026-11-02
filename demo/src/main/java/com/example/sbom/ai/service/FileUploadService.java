package com.example.sbom.ai.service;

import com.example.sbom.ai.dto.AnalysisFeatures;
import com.example.sbom.ai.service.calculator.FeaturesCalculator;
import com.example.sbom.ai.service.parser.ExportJsonParser;
import com.example.sbom.ai.service.validator.FileValidator;
import com.example.sbom.dto.PackageDTO;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.util.List;

@Service
public class FileUploadService {

    private static final Logger log = LoggerFactory.getLogger(FileUploadService.class);

    private final FileValidator fileValidator;
    private final ExportJsonParser jsonParser;
    private final FeaturesCalculator featuresCalculator;
    private final ObjectMapper mapper;

    public FileUploadService(FileValidator fileValidator,
                             ExportJsonParser jsonParser,
                             FeaturesCalculator featuresCalculator) {
        this.fileValidator = fileValidator;
        this.jsonParser = jsonParser;
        this.featuresCalculator = featuresCalculator;
        this.mapper = new ObjectMapper();
    }

    public AnalysisFeatures processUploadedFile(MultipartFile file) throws IOException {
        // 1. Validate file
        fileValidator.validateFile(file);

        // 2. Parse JSON
        JsonNode root = mapper.readTree(file.getInputStream());
        List<PackageDTO> packages = jsonParser.parseExportJson(root);

        // 3. Calculate features
        return featuresCalculator.calculateFeatures(packages);
    }
}