package com.example.sbom.poc;

import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public final class Normalizer {

    private static final Pattern PURL_NPM =
            Pattern.compile("^pkg:npm/([^?#]+)", Pattern.CASE_INSENSITIVE);

    private static final List<Pattern> URL_PATTERNS = List.of(
            Pattern.compile("/npm/(@[^/]+/[^/@]+|[^/@]+)@([^/]+)/", Pattern.CASE_INSENSITIVE),
            Pattern.compile("/package/(@[^/]+/[^/@]+|[^/@]+)@([^/]+)/", Pattern.CASE_INSENSITIVE),
            // Hỗ trợ thêm các pattern phổ biến của unpkg, cdnjs, jsdelivr, skypack:
            Pattern.compile("/npm/(@[^/]+/[^/@]+|[^/@]+)@([^/@]+)$", Pattern.CASE_INSENSITIVE),
            Pattern.compile("/cdn/shop/t/\\d+/assets/(@?[^/@]+)@([^/]+)", Pattern.CASE_INSENSITIVE)
    );

    private Normalizer() {
    }

    /**
     * Chuẩn hóa tên package. Không loại bỏ scope vì @scope/package
     * và package có thể là hai component hoàn toàn khác nhau.
     */
    public static String normalizePackageName(String name) {
        if (name == null) return null;
        return name.strip().toLowerCase(Locale.ROOT);
    }

    /** Giải mã percent-encoding (giữ nguyên dấu '+'). */
    private static String unquote(String value) {
        if (value == null) return "";
        return URLDecoder.decode(value.replace("+", "%2B"), StandardCharsets.UTF_8);
    }

    private static String stripVersion(String nameWithVersion) {
        if (nameWithVersion == null) return "";
        int at = nameWithVersion.indexOf('@');
        return at > 0 ? nameWithVersion.substring(0, at) : nameWithVersion;
    }

    /**
     * Trích xuất tên package từ Package URL dạng npm.
     *
     * pkg:npm/react@18.3.1              -> react
     * pkg:npm/%40scope%2Fpackage@1.0.0  -> @scope/package
     */
    public static String packageNameFromPurl(String purl) {
        if (purl == null || purl.isBlank()) {
            return null;
        }

        Matcher matcher = PURL_NPM.matcher(purl.strip());
        if (!matcher.find()) {
            return null;
        }

        String packagePart = unquote(matcher.group(1));

        if (packagePart.startsWith("@")) {
            // Package có scope: @scope/name[@version]
            String[] parts = packagePart.split("/");
            if (parts.length >= 2) {
                return normalizePackageName(parts[0] + "/" + stripVersion(parts[1]));
            }
            return null;
        }

        // Package không scope: name[@version][/subpath]
        return normalizePackageName(stripVersion(packagePart.split("/")[0]));
    }

    /**
     * Cố gắng nhận diện package từ URL. Chỉ nhận diện khi có dấu hiệu cụ thể:
     * - /npm/<package>@<version>/...
     * - /package/<package>@<version>/...
     *
     * Các URL bundle chung không được tự động gán package.
     */
    public static PackageIdentification inferPackageFromUrl(String url) {
        if (url == null || url.isBlank()) {
            return PackageIdentification.notIdentified();
        }

        String path;
        try {
            String rawPath = URI.create(url).getPath();
            path = rawPath == null ? "" : unquote(rawPath);
        } catch (IllegalArgumentException e) {
            return PackageIdentification.notIdentified();
        }

        for (Pattern pattern : URL_PATTERNS) {
            Matcher matcher = pattern.matcher(path);
            if (matcher.find()) {
                return new PackageIdentification(
                        normalizePackageName(matcher.group(1)),
                        matcher.group(2),
                        "package_name_and_version_in_url",
                        "medium"
                );
            }
        }
        return PackageIdentification.notIdentified();
    }
}

