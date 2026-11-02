package com.example.sbom.gnn.util;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

public final class GraphExportUtil {

    private static final DateTimeFormatter TS_FORMAT = DateTimeFormatter.ofPattern("yyyyMMdd-HHmmssSSS");

    private GraphExportUtil() {
    }

    public static String nowTimestamp() {
        return LocalDateTime.now().format(TS_FORMAT);
    }
}
