package com.example.sbom.service.graph;

import com.example.sbom.model.Edge;
import com.example.sbom.model.Node;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.util.*;

@Service
public class ModuleRankService {
    private static final Logger log = LoggerFactory.getLogger(ModuleRankService.class);

    private static final Map<String, Double> TYPE_WEIGHT = Map.of(
            "runtime", 1.0,
            "dev", 0.5,
            "optional", 0.3,
            "third-party", 0.8
    );

    private static final double DAMPING = 0.85;
    private static final int ITERATIONS = 30;

    public Map<String, Double> calculateRank(List<Node> nodes, List<Edge> edges) {
        Map<String, Double> rank = new HashMap<>();
        if (nodes == null || nodes.isEmpty()) return rank;

        int n = nodes.size();
        for (Node node : nodes) rank.put(node.getId(), 1.0 / n);

        Map<String, List<Edge>> incoming = new HashMap<>();
        Map<String, Integer> outDegree = new HashMap<>();
        for (Node node : nodes) {
            incoming.put(node.getId(), new ArrayList<>());
            outDegree.put(node.getId(), 0);
        }

        for (Edge e : edges) {
            // safety checks
            if (!incoming.containsKey(e.getTo())) continue;
            if (!outDegree.containsKey(e.getFrom())) continue;
            incoming.get(e.getTo()).add(e);
            outDegree.put(e.getFrom(), outDegree.get(e.getFrom()) + 1);
        }

        for (int iter = 0; iter < ITERATIONS; iter++) {
            Map<String, Double> newRank = new HashMap<>();
            for (Node node : nodes) {
                String id = node.getId();
                double sum = 0.0;
                for (Edge edge : incoming.getOrDefault(id, Collections.emptyList())) {
                    double weight = TYPE_WEIGHT.getOrDefault(edge.getType(), 1.0);
                    Double fromRank = rank.get(edge.getFrom());
                    if (fromRank == null) continue;
                    int out = outDegree.getOrDefault(edge.getFrom(), 0);
                    if (out > 0) sum += (fromRank / out) * weight;
                }
                newRank.put(id, (1 - DAMPING) / n + DAMPING * sum);
            }
            rank = newRank;
        }

        double total = rank.values().stream().mapToDouble(Double::doubleValue).sum();
        if (total > 0) {
            rank.replaceAll((k, v) -> v / total);
        }

        log.debug("ModuleRank calculated for {} nodes", nodes.size());
        return rank;
    }
}
