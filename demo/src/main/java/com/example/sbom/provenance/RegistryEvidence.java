package com.example.sbom.provenance;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.URLDecoder;
import java.net.http.*;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.*;
import java.util.regex.Pattern;

record RegistryEvidence(String status, String source, String artifact, String algorithm, String hash, String commit) {
    private static final HttpClient HTTP = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(4)).build();
    private static final ObjectMapper JSON = new ObjectMapper();
    private static final Pattern SRI = Pattern.compile("sha(512|384|256|1)-([A-Za-z0-9+/]+=*)");

    static RegistryEvidence status(String status, String source) {
        return new RegistryEvidence(status, source, null, null, null, null);
    }

    static RegistryEvidence lookup(String purl, String version) {
        if (version.isBlank() || version.equalsIgnoreCase("unknown"))
            return status("MISSING_VERSION", null);
        try {
            if (purl.startsWith("pkg:npm/")) return npm(purl, version);
            if (purl.startsWith("pkg:maven/")) return maven(purl, version);
            return status("UNSUPPORTED_SOURCE", null);
        } catch (IllegalArgumentException e) {
            return status("INVALID_COORDINATES", null);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return status("LOOKUP_ERROR", null);
        } catch (IOException e) {
            return status("LOOKUP_ERROR", e.getMessage());
        }
    }

    private static String coordinate(String purl, String version) {
        String value = purl.substring(purl.indexOf('/') + 1).split("[?#]", 2)[0];
        int separator = value.lastIndexOf('@');
        if (separator > 0) {
            if (!decode(value.substring(separator + 1)).equals(version)) throw new IllegalArgumentException();
            value = value.substring(0, separator);
        }
        return decode(value);
    }

    private static String decode(String s) {
        return URLDecoder.decode(s.replace("+", "%2B"), StandardCharsets.UTF_8);
    }

    private static String encode(String s) {
        return URLEncoder.encode(s, StandardCharsets.UTF_8).replace("+", "%20");
    }

    private static HttpResponse<String> get(String url) throws IOException, InterruptedException {
        HttpRequest req = HttpRequest.newBuilder(URI.create(url)).timeout(Duration.ofSeconds(8)).GET().build();
        try {
            return HTTP.send(req, HttpResponse.BodyHandlers.ofString());
        } catch (IOException e) {
            throw new IOException(url, e);
        }
    }

    private static RegistryEvidence npm(String purl, String version) throws IOException, InterruptedException {
        String name = coordinate(purl, version);
        String source = "https://registry.npmjs.org/" + encode(name) + "/" + encode(version);
        var response = get(source);
        if (response.statusCode() != 200) return failure(response, source);
        var release = JSON.readTree(response.body());
        if (!name.equals(release.path("name").asText()) || !version.equals(release.path("version").asText()))
            return status("RELEASE_MISMATCH", source);
        return npmRelease(source, release);
    }

    static RegistryEvidence npmRelease(String source, JsonNode release) {
        JsonNode dist = release.path("dist");
        String artifact = dist.path("tarball").asText(null);
        String commit = release.path("gitHead").asText(null);
        for (String token : dist.path("integrity").asText().split("\\s+")) {
            var match = SRI.matcher(token);
            if (!match.matches()) continue;
            try {
                byte[] digest = Base64.getDecoder().decode(match.group(2));
                int bits = "1".equals(match.group(1)) ? 160 : Integer.parseInt(match.group(1));
                if (digest.length * 8 == bits)
                    return new RegistryEvidence("RELEASE_FOUND", source, artifact, "SHA-" + match.group(1), HexFormat.of().formatHex(digest), commit);
            } catch (IllegalArgumentException ignored) { /* Try another published digest. */ }
        }
        String sha1 = dist.path("shasum").asText("");
        if (sha1.matches("(?i)[0-9a-f]{40}"))
            return new RegistryEvidence("RELEASE_FOUND", source, artifact, "SHA-1", sha1.toLowerCase(Locale.ROOT), commit);
        return new RegistryEvidence("NO_CHECKSUM", source, artifact, null, null, commit);
    }

    private static RegistryEvidence failure(HttpResponse<?> response, String url) {
        return status(response.statusCode() == 404 ? "NOT_FOUND" : "LOOKUP_ERROR", url);
    }

    private static RegistryEvidence maven(String purl, String version) throws IOException, InterruptedException {
        String[] gav = coordinate(purl, version).split("/");
        if (gav.length != 2 || !version.matches("[a-zA-Z0-9_.+-]+") || !gav[0].matches("[a-zA-Z0-9_-]+(\\.[a-zA-Z0-9_-]+)*")
                || !gav[1].matches("[a-zA-Z0-9_-][a-zA-Z0-9._-]*")) return status("INVALID_COORDINATES", null);
        String type = "jar", classifier = "";
        String query = URI.create(purl.substring(4)).getRawQuery();
        if (query != null) for (String param : query.split("&")) {
            String[] pair = param.split("=", 2);
            if (pair.length != 2 || !pair[1].matches("[a-zA-Z0-9_-]+")) return status("UNSUPPORTED_VARIANT", null);
            if ("type".equals(pair[0])) type = pair[1];
            else if ("classifier".equals(pair[0])) classifier = "-" + pair[1];
            else return status("UNSUPPORTED_VARIANT", null);
        }
        String artifact = "https://repo.maven.apache.org/maven2/" + gav[0].replace('.', '/') + "/" + gav[1] + "/" + version + "/" + gav[1] + "-" + version + classifier + "." + type;
        for (String alg : List.of("256", "1")) {
            String url = artifact + ".sha" + alg;
            var response = get(url);
            if (response.statusCode() == 404) continue;
            if (response.statusCode() != 200) return failure(response, url);
            String hash = response.body().trim().split("\\s+", 2)[0];
            if (hash.matches("(?i)[a-f0-9]{" + ("256".equals(alg) ? 64 : 40) + "}"))
                return new RegistryEvidence("RELEASE_FOUND", url, artifact, "SHA-" + alg, hash.toLowerCase(Locale.ROOT), null);
        }
        var head = HttpRequest.newBuilder(URI.create(artifact)).timeout(Duration.ofSeconds(8)).method("HEAD", HttpRequest.BodyPublishers.noBody()).build();
        var response = HTTP.send(head, HttpResponse.BodyHandlers.discarding());
        return response.statusCode() == 200 ? status("NO_CHECKSUM", artifact) : failure(response, artifact);
    }
}
