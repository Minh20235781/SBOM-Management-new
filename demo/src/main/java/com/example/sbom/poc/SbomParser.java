package com.example.sbom.poc;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Set;

public final class SbomParser {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private SbomParser() {
    }

    /** Chuẩn hóa tên để đối sánh sơ bộ. Không khẳng định hai tên luôn là cùng một package. */
    static String normalizeName(String name) {
        if (name == null) return "";
        return name.strip().toLowerCase(Locale.ROOT);
    }

    private static String text(JsonNode node, String field) {
        if (node == null) return null;
        JsonNode value = node.get(field);
        if (value != null && value.isTextual() && !value.asText().isBlank()) {
            return value.asText();
        }
        return null;
    }

    /** Lấy Package URL nếu có trong component CycloneDX. */
    static String extractPurl(JsonNode component) {
        String purl = text(component, "purl");
        if (purl != null) {
            return purl.strip();
        }

        JsonNode refs = component.get("externalRefs");
        if (refs != null && refs.isArray()) {
            for (JsonNode ref : refs) {
                String type = String.valueOf(text(ref, "referenceType")).toLowerCase(Locale.ROOT);
                String locator = text(ref, "referenceLocator");
                if (Set.of("purl", "package-url").contains(type) && locator != null) {
                    return locator.strip();
                }
            }
        }
        return null;
    }

    static List<StaticComponent> parseCycloneDx(JsonNode data) {
        JsonNode components = data.get("components");
        List<StaticComponent> results = new ArrayList<>();

        if (components == null) {
            return results;
        }
        if (!components.isArray()) {
            throw new IllegalArgumentException("CycloneDX 'components' phải là một danh sách.");
        }

        for (JsonNode component : components) {
            if (!component.isObject()) {
                continue;
            }
            String name = text(component, "name");
            if (name == null) {
                continue;
            }
            results.add(new StaticComponent(
                    name.strip(),
                    normalizeName(name),
                    text(component, "version"),
                    extractPurl(component),
                    "CycloneDX",
                    text(component, "bom-ref"),
                    text(component, "type"),
                    "static_sbom"
            ));
        }
        return results;
    }

    static List<StaticComponent> parseSpdx(JsonNode data) {
        JsonNode packages = data.get("packages");
        List<StaticComponent> results = new ArrayList<>();

        if (packages == null) {
            return results;
        }
        if (!packages.isArray()) {
            throw new IllegalArgumentException("SPDX 'packages' phải là một danh sách.");
        }

        for (JsonNode pkg : packages) {
            if (!pkg.isObject()) {
                continue;
            }
            String name = text(pkg, "name");
            if (name == null) {
                continue;
            }

            String purl = null;
            JsonNode refs = pkg.get("externalRefs");
            if (refs != null && refs.isArray()) {
                for (JsonNode ref : refs) {
                    String category = String.valueOf(text(ref, "referenceCategory")).toLowerCase(Locale.ROOT);
                    String type = String.valueOf(text(ref, "referenceType")).toLowerCase(Locale.ROOT);
                    String locator = text(ref, "referenceLocator");
                    if (category.equals("package-manager") && type.contains("purl") && locator != null) {
                        purl = locator.strip();
                        break;
                    }
                }
            }

            results.add(new StaticComponent(
                    name.strip(),
                    normalizeName(name),
                    text(pkg, "versionInfo"),
                    purl,
                    "SPDX",
                    text(pkg, "SPDXID"),
                    "package",
                    "static_sbom"
            ));
        }
        return results;
    }

    /** Tự nhận diện CycloneDX hoặc SPDX rồi trả về component đã chuẩn hóa từ JsonNode. */
    public static List<StaticComponent> parseJson(JsonNode data) {
        if (data == null || !data.isObject()) {
            throw new IllegalArgumentException("SBOM JSON phải chứa một object ở cấp cao nhất.");
        }

        String bomFormat = String.valueOf(text(data, "bomFormat")).toLowerCase(Locale.ROOT);
        String spdxVersion = text(data, "spdxVersion");

        if (bomFormat.equals("cyclonedx") || data.has("components")) {
            return parseCycloneDx(data);
        }
        if ((spdxVersion != null && spdxVersion.startsWith("SPDX-")) || data.has("packages")) {
            return parseSpdx(data);
        }

        throw new IllegalArgumentException(
                "Không nhận diện được định dạng SBOM. Hỗ trợ CycloneDX JSON và SPDX JSON.");
    }

    /** Phân tích SBOM từ chuỗi JSON content. */
    public static List<StaticComponent> parseContent(String jsonContent) throws IOException {
        if (jsonContent == null || jsonContent.isBlank()) {
            return List.of();
        }
        JsonNode data = MAPPER.readTree(jsonContent);
        return parseJson(data);
    }

    /** Tự nhận diện CycloneDX hoặc SPDX rồi trả về component đã chuẩn hóa từ đường dẫn file. */
    public static List<StaticComponent> parse(Path filePath) throws IOException {
        if (!Files.exists(filePath)) {
            throw new java.io.FileNotFoundException("Không tìm thấy SBOM: " + filePath);
        }
        return parseContent(Files.readString(filePath));
    }
}

