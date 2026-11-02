package com.example.sbom.gnn.explainability.service;

import com.example.sbom.gnn.dto.GraphEdgeDTO;
import com.example.sbom.gnn.dto.GraphExportDTO;
import com.example.sbom.gnn.dto.GraphNodeFeatureDTO;
import com.example.sbom.gnn.explainability.dto.GnnExplanationDTO;
import com.example.sbom.gnn.explainability.dto.NeighborInfluenceDTO;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.stereotype.Service;
import org.springframework.web.client.HttpStatusCodeException;
import org.springframework.web.client.ResourceAccessException;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestTemplate;

import jakarta.annotation.PostConstruct;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** Experimental GNN explainability service (isolated from production ML flows). */
@Service
public class GnnExplainabilityService {

    private static final Logger log = LoggerFactory.getLogger(GnnExplainabilityService.class);

    private final RestTemplate restTemplate = new RestTemplate();

    @Value("${gnn.explainability.base-url:http://localhost:8000}")
    private String baseUrl;

    @Value("${gnn.explainability.model-path:../gnn-training/exports/gat_model.pt}")
    private String modelPath;

    @Value("${gnn.explainability.gcn-model-path:../gnn-training/exports/gcn_model.pt}")
    private String gcnModelPath;

    @Value("${gnn.explainability.model:gat}")
    private String model;

    @Value("${gnn.explainability.heads:4}")
    private int heads;

    @Value("${gnn.explainability.hidden:32}")
    private int hidden;

    @Value("${gnn.explainability.dropout:0.2}")
    private double dropout;

    @Value("${gnn.explainability.seed:42}")
    private int seed;

    @Value("${gnn.explainability.timeout-seconds:12}")
    private int timeoutSeconds;

    @Value("${gnn.explainability.connect-timeout-ms:2000}")
    private int connectTimeoutMs;

    @Value("${gnn.explainability.read-timeout-ms:12000}")
    private int readTimeoutMs;

    @Value("${gnn.explainability.retry-max:2}")
    private int retryMax;

    @Value("${gnn.explainability.retry-backoff-ms:750}")
    private long retryBackoffMs;

    @Value("${gnn.explainability.influence-top-k:3}")
    private int influenceTopK;

    @Value("${gnn.explainability.attention-threshold:0.6}")
    private double attentionThreshold;

    @Value("${gnn.explainability.propagation-threshold:0.7}")
    private double propagationThreshold;

    @Value("${gnn.explainability.epss-threshold:0.7}")
    private double epssThreshold;

    private String resolveModel(GraphExportDTO request) {
        if (request == null || request.getModel() == null || request.getModel().isBlank()) {
            return model;
        }
        String requested = request.getModel().trim().toLowerCase();
        if (!"gcn".equals(requested) && !"gat".equals(requested)) {
            throw new IllegalArgumentException("Unsupported GNN model: " + request.getModel());
        }
        return requested;
    }

    private String resolveModelPath(String modelName) {
        if ("gcn".equalsIgnoreCase(modelName)) {
            return gcnModelPath;
        }
        return modelPath;
    }

    @PostConstruct
    public void configureTimeouts() {
        SimpleClientHttpRequestFactory factory = new SimpleClientHttpRequestFactory();
        factory.setConnectTimeout(connectTimeoutMs);
        factory.setReadTimeout(readTimeoutMs);
        restTemplate.setRequestFactory(factory);
    }

    public List<GnnExplanationDTO> analyze(GraphExportDTO request) {
        if (request == null) {
            throw new IllegalArgumentException("explainability payload is required");
        }

        List<GraphNodeFeatureDTO> nodes = request.getNodes() != null ? request.getNodes() : List.of();
        List<GraphEdgeDTO> edges = request.getEdges() != null ? request.getEdges() : List.of();

        if (nodes.isEmpty()) {
            log.warn("GNN explainability skipped: empty nodes list");
            return Collections.emptyList();
        }

        PythonPredictionResponse response = callExplainabilityWithRetry(request);
        Map<Integer, PythonPredictionItem> predictionById = indexPredictions(response);
        Map<Integer, GraphNodeFeatureDTO> nodeIndex = indexNodes(nodes);
        Map<Integer, List<Integer>> incomingNeighbors = buildIncomingMap(edges);

        // Tính percentile rank cho tất cả nodes
        Map<Integer, Double> percentileRanks = computePercentileRanks(nodes);

        List<GnnExplanationDTO> explanations = new ArrayList<>();
        for (GraphNodeFeatureDTO node : nodes) {
            if (node == null || node.getNodeId() == null) {
                continue;
            }
            PythonPredictionItem prediction = predictionById.get(node.getNodeId());
            List<NeighborInfluenceDTO> neighbors = buildInfluentialNeighbors(node.getNodeId(), incomingNeighbors,
                    predictionById, nodeIndex);

            GnnExplanationDTO dto = new GnnExplanationDTO();
            dto.setPackageName(node.getPackageName());
            dto.setPredictedRisk(prediction != null ? prediction.predictedRisk : "UNKNOWN");
            dto.setInfluentialNeighbors(neighbors);
            dto.setAttentionScores(buildAttentionScores(prediction, node));
            dto.setExplanationText(buildExplanationText(node, prediction, neighbors));
            dto.setPercentileRank(percentileRanks.get(node.getNodeId()));
            explanations.add(dto);
        }

        log.info("GNN explainability generated: nodes={}, explanations={}", nodes.size(), explanations.size());
        return explanations;
    }

    /**
     * Tính percentile rank cho moduleRank.
     * Percentile = package cao hơn bao nhiêu % packages khác.
     * Ví dụ: percentileRank = 95.0 → package thuộc Top 5% phổ biến nhất.
     */
    private Map<Integer, Double> computePercentileRanks(List<GraphNodeFeatureDTO> nodes) {
        if (nodes == null || nodes.isEmpty()) {
            return Collections.emptyMap();
        }

        // Thu thập tất cả moduleRank values
        List<Double> ranks = new ArrayList<>();
        for (GraphNodeFeatureDTO node : nodes) {
            if (node != null) {
                ranks.add(node.getModuleRank());
            }
        }

        if (ranks.isEmpty()) {
            return Collections.emptyMap();
        }

        // Sắp xếp để tính percentile
        List<Double> sortedRanks = new ArrayList<>(ranks);
        Collections.sort(sortedRanks);

        // Map nodeId -> percentile rank
        Map<Integer, Double> percentileMap = new HashMap<>();
        for (GraphNodeFeatureDTO node : nodes) {
            if (node == null || node.getNodeId() == null) {
                continue;
            }

            double rank = node.getModuleRank();
            // Đếm số lượng ranks nhỏ hơn rank hiện tại
            int countBelow = 0;
            for (Double sortedRank : sortedRanks) {
                if (sortedRank < rank) {
                    countBelow++;
                }
            }

            // Percentile = (countBelow / total) * 100
            double percentile = (countBelow * 100.0) / sortedRanks.size();
            percentileMap.put(node.getNodeId(), Math.round(percentile * 10.0) / 10.0); // Làm tròn 1 chữ số
        }

        return percentileMap;
    }

    private PythonPredictionResponse callExplainabilityWithRetry(GraphExportDTO request) {
        RestClientException last = null;
        int attempts = Math.max(1, retryMax + 1);
        for (int attempt = 1; attempt <= attempts; attempt++) {
            try {
                return callExplainability(request);
            } catch (ResourceAccessException ex) {
                last = ex;
                if (attempt >= attempts) {
                    break;
                }
                log.warn("GNN explainability timeout (attempt {}/{}): {}", attempt, attempts, ex.getMessage());
                sleepBackoff(attempt);
            } catch (HttpStatusCodeException ex) {
                if (ex.getStatusCode().is4xxClientError()) {
                    throw ex;
                }
                last = ex;
                if (attempt >= attempts) {
                    break;
                }
                log.warn("GNN explainability retry on HTTP {} (attempt {}/{}): {}",
                        ex.getStatusCode(), attempt, attempts, ex.getMessage());
                sleepBackoff(attempt);
            } catch (RestClientException ex) {
                last = ex;
                if (attempt >= attempts) {
                    break;
                }
                log.warn("GNN explainability retry (attempt {}/{}): {}", attempt, attempts, ex.getMessage());
                sleepBackoff(attempt);
            }
        }

        throw new IllegalStateException("GNN explainability failed after retries", last);
    }

    private void sleepBackoff(int attempt) {
        if (retryBackoffMs <= 0) {
            return;
        }
        try {
            Thread.sleep(retryBackoffMs * attempt);
        } catch (InterruptedException ie) {
            Thread.currentThread().interrupt();
        }
    }

    private PythonPredictionResponse callExplainability(GraphExportDTO request) {
        String url = baseUrl + "/explainability";
        String resolvedModel = resolveModel(request);
        String resolvedModelPath = resolveModelPath(resolvedModel);
        Map<String, Object> payload = new HashMap<>();
        payload.put("model_path", resolvedModelPath);
        payload.put("model", resolvedModel);
        payload.put("data", buildGraphPayload(request));
        payload.put("heads", heads);
        payload.put("hidden", hidden);
        payload.put("dropout", dropout);
        payload.put("seed", seed);
        payload.put("timeout_seconds", timeoutSeconds);

        log.info(
            "Calling GNN explainability: url={}, model={}, timeoutSeconds={}",
            url,
            resolvedModel,
            timeoutSeconds
        );

        ResponseEntity<PythonPredictionResponse> response = restTemplate.exchange(
                url,
                HttpMethod.POST,
                new HttpEntity<>(payload),
                PythonPredictionResponse.class
        );

        if (!response.getStatusCode().is2xxSuccessful() || response.getBody() == null) {
            throw new IllegalStateException("Explainability response was empty");
        }

        return response.getBody();
    }

    private Map<String, Object> buildGraphPayload(GraphExportDTO exportDTO) {
        Map<String, Object> payload = new HashMap<>();
        List<Map<String, Object>> nodes = new ArrayList<>();
        List<Map<String, Object>> edges = new ArrayList<>();

        if (exportDTO.getNodes() != null) {
            for (GraphNodeFeatureDTO node : exportDTO.getNodes()) {
                if (node == null) {
                    continue;
                }
                Map<String, Object> nodeMap = new HashMap<>();
                nodeMap.put("nodeId", node.getNodeId());
                nodeMap.put("packageName", node.getPackageName());

                Map<String, Object> features = new HashMap<>();
                features.put("moduleRank", node.getModuleRank());
                features.put("maxCvss", node.getMaxCvss());
                features.put("avgCvss", node.getAvgCvss());
                features.put("maxEpss", node.getMaxEpss());
                features.put("avgEpss", node.getAvgEpss());
                features.put("kevCount", node.getKevCount());
                features.put("vulnerabilityCount", node.getVulnerabilityCount());
                features.put("severityWeight", node.getSeverityWeight());

                nodeMap.put("features", features);
                nodes.add(nodeMap);
            }
        }

        if (exportDTO.getEdges() != null) {
            for (GraphEdgeDTO edge : exportDTO.getEdges()) {
                if (edge == null) {
                    continue;
                }
                Map<String, Object> edgeMap = new HashMap<>();
                edgeMap.put("source", edge.getSource());
                edgeMap.put("target", edge.getTarget());
                edges.add(edgeMap);
            }
        }

        payload.put("nodes", nodes);
        payload.put("edges", edges);
        return payload;
    }

    private Map<Integer, PythonPredictionItem> indexPredictions(PythonPredictionResponse response) {
        if (response == null || response.items == null) {
            return Collections.emptyMap();
        }
        Map<Integer, PythonPredictionItem> index = new HashMap<>();
        for (PythonPredictionItem item : response.items) {
            index.put(item.nodeId, item);
        }
        return index;
    }

    private Map<Integer, GraphNodeFeatureDTO> indexNodes(List<GraphNodeFeatureDTO> nodes) {
        Map<Integer, GraphNodeFeatureDTO> index = new HashMap<>();
        for (GraphNodeFeatureDTO node : nodes) {
            if (node != null && node.getNodeId() != null) {
                index.put(node.getNodeId(), node);
            }
        }
        return index;
    }

    private Map<Integer, List<Integer>> buildIncomingMap(List<GraphEdgeDTO> edges) {
        Map<Integer, List<Integer>> incoming = new HashMap<>();
        for (GraphEdgeDTO edge : edges) {
            if (edge == null || edge.getSource() == null || edge.getTarget() == null) {
                continue;
            }
            incoming.computeIfAbsent(edge.getTarget(), key -> new ArrayList<>()).add(edge.getSource());
        }
        return incoming;
    }

    private List<NeighborInfluenceDTO> buildInfluentialNeighbors(int nodeId,
                                                                 Map<Integer, List<Integer>> incoming,
                                                                 Map<Integer, PythonPredictionItem> predictionById,
                                                                 Map<Integer, GraphNodeFeatureDTO> nodeIndex) {
        List<Integer> neighbors = incoming.getOrDefault(nodeId, List.of());
        if (neighbors.isEmpty()) {
            return List.of();
        }

        List<NeighborInfluenceDTO> influences = new ArrayList<>();
        for (Integer neighborId : neighbors) {
            GraphNodeFeatureDTO neighborNode = nodeIndex.get(neighborId);
            PythonPredictionItem neighborPrediction = predictionById.get(neighborId);

            double attention = neighborPrediction != null ? neighborPrediction.attentionScore : 0.0;
            double propagation = neighborPrediction != null ? neighborPrediction.propagationRisk : 0.0;
            double influenceScore = 0.6 * attention + 0.4 * propagation;

            NeighborInfluenceDTO dto = new NeighborInfluenceDTO();
            dto.setPackageName(neighborNode != null ? neighborNode.getPackageName() : "node-" + neighborId);
            dto.setInfluenceScore(influenceScore);
            dto.setRiskLevel(neighborPrediction != null ? neighborPrediction.predictedRisk : "UNKNOWN");
            influences.add(dto);
        }

        influences.sort(Comparator.comparingDouble(NeighborInfluenceDTO::getInfluenceScore).reversed());
        if (influences.size() > influenceTopK) {
            return new ArrayList<>(influences.subList(0, influenceTopK));
        }
        return influences;
    }

    private Map<String, Double> buildAttentionScores(PythonPredictionItem prediction, GraphNodeFeatureDTO node) {
        Map<String, Double> scores = new LinkedHashMap<>();
        scores.put("selfAttention", prediction != null ? prediction.attentionScore : 0.0);
        scores.put("propagationRisk", prediction != null ? prediction.propagationRisk : 0.0);
        scores.put("maxEpss", node != null ? node.getMaxEpss() : 0.0);
        return scores;
    }

    private String buildExplanationText(GraphNodeFeatureDTO node,
                                        PythonPredictionItem prediction,
                                        List<NeighborInfluenceDTO> neighbors) {
        List<String> reasons = new ArrayList<>();

        if (neighbors.stream().anyMatch(n -> "HIGH".equalsIgnoreCase(n.getRiskLevel())
                && n.getInfluenceScore() >= propagationThreshold)) {
            reasons.add("connected to actively exploited dependency");
        }

        if (neighbors.stream().anyMatch(n -> "HIGH".equalsIgnoreCase(n.getRiskLevel()))) {
            reasons.add("high-risk neighboring packages");
        }

        if (prediction != null && prediction.propagationRisk >= propagationThreshold) {
            reasons.add("high propagation exposure");
        }

        if (node != null && node.getMaxEpss() >= epssThreshold) {
            reasons.add("high EPSS central dependency");
        }

        if (prediction != null && prediction.attentionScore >= attentionThreshold) {
            reasons.add("attention highlights critical dependency paths");
        }

        if (reasons.isEmpty()) {
            reasons.add("limited graph signal; explanation pending");
        }

        StringBuilder builder = new StringBuilder("Package risk increased because:\n\n");
        for (String reason : reasons) {
            builder.append("* ").append(reason).append("\n");
        }
        return builder.toString().trim();
    }

    private static class PythonPredictionResponse {
        public List<PythonPredictionItem> items;
    }

    private static class PythonPredictionItem {
        public int nodeId;
        public String packageName;
        public String predictedRisk;
        public double confidenceScore;
        public double attentionScore;
        public double propagationRisk;
    }
}
