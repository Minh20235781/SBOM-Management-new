package com.example.sbom.service.validation;

import com.example.sbom.dto.ValidationIssueDTO;
import org.springframework.stereotype.Service;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.File;
import java.util.*;

@Service
public class ConsistencyValidationService {

    public Map<String, String> extractBuildDependencies(String repoPath, String repoName) {
        File pomFile = resolvePomFile(repoPath, repoName);
        if (pomFile == null || !pomFile.exists()) {
            return Collections.emptyMap();
        }

        Map<String, String> result = new HashMap<>();
        try {
            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
            factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
            factory.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
            factory.setExpandEntityReferences(false);

            DocumentBuilder builder = factory.newDocumentBuilder();
            Document doc = builder.parse(pomFile);
            Element project = doc.getDocumentElement();
            NodeList children = project.getChildNodes();

            for (int i = 0; i < children.getLength(); i++) {
                if (!(children.item(i) instanceof Element child)) continue;
                if (!"dependencies".equals(child.getTagName())) continue;

                NodeList deps = child.getChildNodes();
                for (int j = 0; j < deps.getLength(); j++) {
                    if (!(deps.item(j) instanceof Element dep)) continue;
                    if (!"dependency".equals(dep.getTagName())) continue;

                    String artifactId = getChildText(dep, "artifactId");
                    if (artifactId == null || artifactId.isBlank()) continue;

                    String version = getChildText(dep, "version");
                    String scope = getChildText(dep, "scope");
                    String type = getChildText(dep, "type");
                    if (scope != null && scope.equalsIgnoreCase("test")) continue;
                    if (type != null && type.equalsIgnoreCase("pom") && scope != null && scope.equalsIgnoreCase("import")) continue;

                    String existing = result.get(artifactId);
                    if (existing == null || compareVersions(version, existing) > 0) {
                        result.put(artifactId, version);
                    }
                }
            }
        } catch (Exception ex) {
            return Collections.emptyMap();
        }

        return result;
    }

    public List<ValidationIssueDTO> detectIssues(
            Map<String, String> sbomDeps,
            Set<String> graphDeps,
            Map<String, String> buildDeps,
            Map<String, String> scannerDeps
    ) {
        List<ValidationIssueDTO> issues = new ArrayList<>();

        Set<String> allSources = new HashSet<>();
        allSources.addAll(graphDeps);
        allSources.addAll(buildDeps.keySet());
        allSources.addAll(scannerDeps.keySet());

        for (String dep : allSources) {
            Set<String> versions = new HashSet<>();
            if (sbomDeps.get(dep) != null && !sbomDeps.get(dep).isBlank()) versions.add(sbomDeps.get(dep));
            if (buildDeps.get(dep) != null && !buildDeps.get(dep).isBlank()) versions.add(buildDeps.get(dep));
            if (scannerDeps.get(dep) != null && !scannerDeps.get(dep).isBlank()) versions.add(scannerDeps.get(dep));
            if (versions.size() > 1) {
                issues.add(issue("VERSION_MISMATCH", dep, "MEDIUM"));
            }
        }

        return issues;
    }

    private ValidationIssueDTO issue(String type, String packageName, String severity) {
        ValidationIssueDTO dto = new ValidationIssueDTO();
        dto.setType(type);
        dto.setPackageName(packageName);
        dto.setSeverity(severity);
        return dto;
    }

    private File resolvePomFile(String repoPath, String repoName) {
        if (repoPath != null && !repoPath.isBlank()) {
            File direct = new File(repoPath, "pom.xml");
            if (direct.exists()) return direct;
        }

        String baseDir = System.getProperty("user.dir");
        File currentPom = new File(baseDir, "pom.xml");
        if (currentPom.exists()) return currentPom;

        if (repoName != null && !repoName.isBlank()) {
            File byRepo = new File(baseDir, repoName + File.separator + "pom.xml");
            if (byRepo.exists()) return byRepo;
        }

        File demoPom = new File(baseDir + File.separator + "demo", "pom.xml");
        if (demoPom.exists()) return demoPom;

        return null;
    }

    private String getChildText(Element element, String tag) {
        NodeList nodes = element.getElementsByTagName(tag);
        if (nodes.getLength() == 0) return null;
        return nodes.item(0).getTextContent();
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
}
