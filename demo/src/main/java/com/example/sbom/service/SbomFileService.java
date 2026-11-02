package com.example.sbom.service;

import com.example.sbom.entity.Module;
import com.example.sbom.entity.SbomFile;
import com.example.sbom.entity.SbomFileHistory;
import com.example.sbom.repository.ModuleRepository;
import com.example.sbom.repository.ProjectRepository;
import com.example.sbom.repository.SbomFileHistoryRepository;
import com.example.sbom.repository.SbomFileRepository;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.server.ResponseStatusException;

import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;

/**
 * Records metadata about SBOM files uploaded to a module. The actual file
 * content is what existing scan/upload code paths handle; this service
 * only tracks which file belongs to which module, plus a content hash
 * so duplicates can be detected.
 */
@Service
public class SbomFileService {

    private static final Logger log = LoggerFactory.getLogger(SbomFileService.class);

    private final SbomFileRepository sbomFileRepository;
    private final SbomFileHistoryRepository historyRepository;
    private final ModuleRepository moduleRepository;
    private final ProjectRepository projectRepository;
    private final ObjectMapper objectMapper;

    public SbomFileService(SbomFileRepository sbomFileRepository,
                           SbomFileHistoryRepository historyRepository,
                           ModuleRepository moduleRepository,
                           ProjectRepository projectRepository,
                           ObjectMapper objectMapper) {
        this.sbomFileRepository = sbomFileRepository;
        this.historyRepository = historyRepository;
        this.moduleRepository = moduleRepository;
        this.projectRepository = projectRepository;
        this.objectMapper = objectMapper;
    }

    @Transactional(readOnly = true)
    public List<SbomFile> listByModule(Long projectId, Long moduleId) {
        Module m = requireModule(projectId, moduleId);
        return sbomFileRepository.findByModuleIdOrderByUploadedAtDesc(m.getId());
    }

    @Transactional
    public SbomFile recordUpload(Long projectId, Long moduleId, MultipartFile file) {
        Module m = requireModule(projectId, moduleId);
        if (file == null || file.isEmpty()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "File is required");
        }

        SbomFile sbom = new SbomFile();
        sbom.setModuleId(m.getId());
        sbom.setFileName(file.getOriginalFilename() == null ? "sbom.json" : file.getOriginalFilename());
        sbom.setSizeBytes(file.getSize());
        sbom.setSource("UPLOAD");
        sbom.setScanStatus(SbomFile.ScanStatus.PENDING);

        try {
            byte[] bytes = file.getBytes();
            sbom.setSha256(sha256(bytes));
        } catch (IOException e) {
            log.warn("SbomFileService: failed to read bytes for upload, sha256 will be null", e);
        }

        sbom = sbomFileRepository.saveAndFlush(sbom);
        recordHistory(sbom, SbomFileHistory.ChangeType.UPLOADED, "Uploaded by user", serialize(sbom));
        log.info("SbomFileService: recorded upload id={} moduleId={} fileName='{}'",
                sbom.getId(), m.getId(), sbom.getFileName());
        return sbom;
    }

    @Transactional
    public SbomFile markScanCompleted(Long sbomFileId) {
        SbomFile sbom = sbomFileRepository.findById(sbomFileId)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND,
                        "SbomFile not found: id=" + sbomFileId));
        sbom.setScanStatus(SbomFile.ScanStatus.COMPLETED);
        sbom = sbomFileRepository.saveAndFlush(sbom);
        recordHistory(sbom, SbomFileHistory.ChangeType.SCAN_COMPLETED, "Scan finished", serialize(sbom));
        return sbom;
    }

    @Transactional
    public void delete(Long projectId, Long moduleId, Long sbomFileId) {
        SbomFile sbom = sbomFileRepository.findById(sbomFileId)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND,
                        "SbomFile not found: id=" + sbomFileId));
        Module m = requireModule(projectId, moduleId);
        if (!sbom.getModuleId().equals(m.getId())) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND,
                    "SbomFile " + sbomFileId + " does not belong to module " + moduleId);
        }
        recordHistory(sbom, SbomFileHistory.ChangeType.DELETED, "Deleted by user", serialize(sbom));
        sbomFileRepository.delete(sbom);
        log.info("SbomFileService: deleted id={}", sbomFileId);
    }

    @Transactional(readOnly = true)
    public List<SbomFileHistory> getHistory(Long projectId, Long moduleId, Long sbomFileId) {
        SbomFile sbom = sbomFileRepository.findById(sbomFileId)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND,
                        "SbomFile not found: id=" + sbomFileId));
        requireModule(projectId, moduleId);
        if (!sbom.getModuleId().equals(moduleId)) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND,
                    "SbomFile " + sbomFileId + " does not belong to module " + moduleId);
        }
        return historyRepository.findBySbomFileIdOrderByChangedAtDesc(sbomFileId);
    }

    private Module requireModule(Long projectId, Long moduleId) {
        if (!projectRepository.existsById(projectId)) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND,
                    "Project not found: id=" + projectId);
        }
        Module m = moduleRepository.findById(moduleId)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND,
                        "Module not found: id=" + moduleId));
        if (!m.getProjectId().equals(projectId)) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND,
                    "Module " + moduleId + " does not belong to project " + projectId);
        }
        return m;
    }

    private void recordHistory(SbomFile sbom, SbomFileHistory.ChangeType type, String note, String snapshotJson) {
        SbomFileHistory h = new SbomFileHistory();
        h.setSbomFileId(sbom.getId());
        h.setModuleId(sbom.getModuleId());
        h.setProjectId(moduleRepository.findById(sbom.getModuleId())
                .map(Module::getProjectId).orElse(-1L));
        h.setChangeType(type);
        h.setScanStatus(sbom.getScanStatus() == null ? null : sbom.getScanStatus().name());
        h.setNote(note);
        h.setSnapshotJson(snapshotJson);
        historyRepository.save(h);
    }

    private String serialize(SbomFile sbom) {
        try {
            Map<String, Object> snapshot = Map.of(
                    "id", sbom.getId(),
                    "moduleId", sbom.getModuleId(),
                    "fileName", sbom.getFileName(),
                    "sha256", sbom.getSha256() == null ? "" : sbom.getSha256(),
                    "sizeBytes", sbom.getSizeBytes() == null ? 0 : sbom.getSizeBytes(),
                    "source", sbom.getSource() == null ? "" : sbom.getSource(),
                    "scanStatus", sbom.getScanStatus() == null ? "" : sbom.getScanStatus().name(),
                    "uploadedAt", sbom.getUploadedAt() == null ? "" : sbom.getUploadedAt().toString()
            );
            return objectMapper.writeValueAsString(snapshot);
        } catch (JsonProcessingException e) {
            log.warn("SbomFileService: failed to serialize snapshot id={}", sbom.getId(), e);
            return "{}";
        }
    }

    private static String sha256(byte[] bytes) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            return HexFormat.of().formatHex(md.digest(bytes));
        } catch (NoSuchAlgorithmException e) {
            return null;
        }
    }
}
