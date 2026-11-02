package com.example.sbom.poc;

import java.util.List;
import java.util.Map;

/** Báo cáo đối sánh gồm phần tổng hợp và danh sách kết quả chi tiết. */
public record MatchReport(Summary summary, List<MatchResult> results) {

    public record Summary(
            int staticComponentCount,
            int runtimeResourceCount,
            int resultCount,
            Map<String, Integer> statusCounts
    ) {
    }
}

