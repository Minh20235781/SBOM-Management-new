import json
import logging
import math
import random
from collections import deque
from typing import Dict, Iterable, List, Optional, Tuple

import torch
from torch_geometric.data import Data
from sklearn.preprocessing import StandardScaler

logger = logging.getLogger(__name__)

BASE_FEATURE_ORDER = [
    "moduleRank",
    "vulnerabilityCount",
    "kevCount",
    "epssSignal",
    "cvssSignal",
    "inDegree",
    "outDegree",
    "transitiveDependencyCount",
    "transitiveDependentCount",
    "dependencyDepth",
    "shortestPathToVulnerable",
    "vulnerableReachability",
    "reachableHighRiskNodes",
    "vulnerableNeighborRatio",
    "pagerank",
    "betweennessCentrality",
    "eigenvectorCentrality",
    "closenessCentrality",
    "releaseAge",
    "latestVersionGap",
    "maintainerCount",
    "updateFrequency",
    "deprecatedFlag",
    "archivedRepoFlag",
    "vulnerableTransitiveCount",
    "directVsTransitiveRatio",
    "historicalVulnerabilityDensity",
    "recentCveCount",
    "exploitChainExposure",
    "neighborRiskMean",
    "neighborRiskMax",
    "upstreamRiskScore",
    "downstreamRiskScore",
    "propagationDepth",
    "propagationDecayScore",
    "runtimeDependencyFlag",
    "optionalDependencyFlag",
    "testDependencyFlag",
    "criticalPathDependency",
    "internetExposedDependency",
]

# Mutable view for legacy utilities that rely on global feature order.
FEATURE_ORDER = list(BASE_FEATURE_ORDER)

CENTRALITY_FEATURES = {
    "pagerank",
    "betweennessCentrality",
    "eigenvectorCentrality",
    "closenessCentrality",
}

LOG1P_FEATURES = {
    "vulnerabilityCount",
    "kevCount",
    "transitiveDependencyCount",
    "transitiveDependentCount",
    "vulnerableReachability",
    "reachableHighRiskNodes",
    "vulnerableTransitiveCount",
    "recentCveCount",
    "neighborRiskMean",
    "neighborRiskMax",
    "upstreamRiskScore",
    "downstreamRiskScore",
    "propagationDecayScore",
}

LABELS = ["low", "medium", "high"]

DROP_FEATURES = {
    "kevCount",
    "releaseAge",
    "latestVersionGap",
    "maintainerCount",
    "updateFrequency",
    "deprecatedFlag",
    "archivedRepoFlag",
    "recentCveCount",
    "runtimeDependencyFlag",
    "optionalDependencyFlag",
    "testDependencyFlag",
    "criticalPathDependency",
    "internetExposedDependency",
}

COLLINEARITY_DROPS = {
    "vulnerableTransitiveCount",
    "neighborRiskMean",
    "historicalVulnerabilityDensity",
}


def load_graph(path: str) -> Tuple[Data, List[str]]:
    """
    Load a JSON graph export and convert it into a PyTorch Geometric Data object.
    """
    with open(path, "r", encoding="utf-8") as handle:
        payload = json.load(handle)

    nodes = payload.get("nodes", [])
    edges = payload.get("edges", [])

    if not nodes:
        raise ValueError("Graph export has no nodes")

    node_records = sorted(nodes, key=lambda n: n.get("nodeId", 0))
    id_to_idx: Dict[int, int] = {}
    for idx, node in enumerate(node_records):
        node_id = int(node.get("nodeId", idx))
        id_to_idx[node_id] = idx

    edge_index = _build_edge_index(edges, id_to_idx)
    global FEATURE_ORDER

    raw_features, aux = _engineer_features(node_records, edge_index)
    raw_features, pruned_order, dropped = _prune_features(raw_features, list(BASE_FEATURE_ORDER))
    if dropped:
        logger.info("Dropped features: %s", ", ".join(dropped))
    FEATURE_ORDER = pruned_order

    transformed = _apply_transforms(raw_features, FEATURE_ORDER)
    _log_feature_diagnostics(transformed, FEATURE_ORDER)

    scaler = StandardScaler()
    normalized = scaler.fit_transform(transformed)

    x = torch.tensor(normalized, dtype=torch.float)
    y = _build_labels(raw_features, aux, node_records)

    data = Data(x=x, edge_index=edge_index, y=y)
    data.feature_names = list(FEATURE_ORDER)
    data.raw_features = torch.tensor(raw_features, dtype=torch.float)
    data.transformed_features = torch.tensor(transformed, dtype=torch.float)
    data.risk_proxy = torch.tensor(aux.get("upstream_risk", []), dtype=torch.float)

    logger.info("Loaded graph: nodes=%s, edges=%s", x.size(0), edge_index.size(1))

    return data, LABELS


def build_graph_from_payload(
    payload: Dict,
    expected_features: Optional[List[str]] = None,
    run_diagnostics: bool = False,
) -> Tuple[Data, List[Dict], List[str]]:
    nodes = payload.get("nodes", [])
    edges = payload.get("edges", [])

    if not nodes:
        raise ValueError("Graph export has no nodes")

    nodes_sorted = sorted(nodes, key=lambda n: n.get("nodeId", 0))
    id_to_idx: Dict[int, int] = {}
    for idx, node in enumerate(nodes_sorted):
        node_id = int(node.get("nodeId", idx))
        id_to_idx[node_id] = idx

    edge_index = _build_edge_index(edges, id_to_idx)
    raw_features, aux = _engineer_features(nodes_sorted, edge_index)

    if expected_features is None:
        raw_features, feature_order, dropped = _prune_features(raw_features, list(BASE_FEATURE_ORDER))
        if dropped:
            logger.info("Dropped features: %s", ", ".join(dropped))
    else:
        feature_order = list(expected_features)
        raw_features = _align_features(raw_features, list(BASE_FEATURE_ORDER), feature_order)

    transformed = _apply_transforms(raw_features, feature_order)
    if run_diagnostics:
        _log_feature_diagnostics(transformed, feature_order)

    scaler = StandardScaler()
    normalized = scaler.fit_transform(transformed)

    data = Data(x=torch.tensor(normalized, dtype=torch.float), edge_index=edge_index)
    data.feature_names = list(feature_order)
    data.raw_features = torch.tensor(raw_features, dtype=torch.float)
    data.transformed_features = torch.tensor(transformed, dtype=torch.float)
    data.risk_proxy = torch.tensor(aux.get("upstream_risk", []), dtype=torch.float)

    return data, nodes_sorted, feature_order


def _get_feature_block(node: Dict) -> Dict:
    if isinstance(node.get("features"), dict):
        return node.get("features")
    return node


def _get_float(block: Dict, key: str, default: float = 0.0) -> float:
    value = block.get(key, default)
    try:
        return float(value)
    except (TypeError, ValueError):
        return float(default)


def _build_edge_index(edges: List[Dict], id_to_idx: Dict[int, int]) -> torch.Tensor:
    src_list: List[int] = []
    dst_list: List[int] = []

    for edge in edges:
        if edge is None:
            continue
        src = edge.get("source")
        dst = edge.get("target")
        if src is None or dst is None:
            continue
        if src not in id_to_idx or dst not in id_to_idx:
            continue
        src_list.append(id_to_idx[src])
        dst_list.append(id_to_idx[dst])

    if not src_list:
        return torch.empty((2, 0), dtype=torch.long)

    return torch.tensor([src_list, dst_list], dtype=torch.long)


def _build_adjacency(edge_index: torch.Tensor, num_nodes: int) -> Tuple[List[List[int]], List[List[int]], List[List[int]]]:
    upstream = [[] for _ in range(num_nodes)]
    downstream = [[] for _ in range(num_nodes)]
    undirected = [[] for _ in range(num_nodes)]

    if edge_index.numel() == 0:
        return upstream, downstream, undirected

    src, dst = edge_index
    for s, d in zip(src.tolist(), dst.tolist()):
        downstream[s].append(d)
        upstream[d].append(s)
        undirected[s].append(d)
        undirected[d].append(s)

    return upstream, downstream, undirected


def _engineer_features(nodes: List[Dict], edge_index: torch.Tensor) -> Tuple[List[List[float]], Dict[str, List[float]]]:
    num_nodes = len(nodes)
    upstream, downstream, undirected = _build_adjacency(edge_index, num_nodes)

    module_rank: List[float] = []
    vulnerability_count: List[float] = []
    kev_count: List[float] = []
    avg_cvss: List[float] = []
    max_cvss: List[float] = []
    avg_epss: List[float] = []
    max_epss: List[float] = []
    release_age: List[float] = []
    latest_version_gap: List[float] = []
    maintainer_count: List[float] = []
    update_frequency: List[float] = []
    deprecated_flag: List[float] = []
    archived_flag: List[float] = []
    recent_cve_count: List[float] = []
    runtime_flag: List[float] = []
    optional_flag: List[float] = []
    test_flag: List[float] = []
    critical_path_flag: List[float] = []
    internet_exposed_flag: List[float] = []

    for node in nodes:
        block = _get_feature_block(node)
        module_rank.append(_get_float(block, "moduleRank"))
        vulnerability_count.append(_get_float(block, "vulnerabilityCount"))
        kev_count.append(_get_float(block, "kevCount"))
        avg_cvss.append(_get_float(block, "avgCvss"))
        max_cvss.append(_get_float(block, "maxCvss"))
        avg_epss.append(_get_float(block, "avgEpss"))
        max_epss.append(_get_float(block, "maxEpss"))
        release_age.append(_get_float(block, "releaseAge"))
        latest_version_gap.append(_get_float(block, "latestVersionGap"))
        maintainer_count.append(_get_float(block, "maintainerCount"))
        update_frequency.append(_get_float(block, "updateFrequency"))
        deprecated_flag.append(_get_float(block, "deprecatedFlag"))
        archived_flag.append(_get_float(block, "archivedRepoFlag"))
        recent_cve_count.append(_get_float(block, "recentCveCount"))
        runtime_flag.append(_get_float(block, "runtimeDependencyFlag"))
        optional_flag.append(_get_float(block, "optionalDependencyFlag"))
        test_flag.append(_get_float(block, "testDependencyFlag"))
        critical_path_flag.append(_get_float(block, "criticalPathDependency"))
        internet_exposed_flag.append(_get_float(block, "internetExposedDependency"))

    epss_signal = [
        _blend_log_epss(max_epss[i], avg_epss[i])
        for i in range(num_nodes)
    ]
    cvss_signal = [
        _blend_log_cvss(max_cvss[i], avg_cvss[i])
        for i in range(num_nodes)
    ]

    in_degree = [float(len(upstream[idx])) for idx in range(num_nodes)]
    out_degree = [float(len(downstream[idx])) for idx in range(num_nodes)]

    base_risk = _base_risk_scores(
        vulnerability_count,
        kev_count,
        deprecated_flag,
        archived_flag,
    )

    neighbor_risk_mean, neighbor_risk_max = _neighbor_risk(upstream, base_risk)

    vulnerable_nodes = {
        idx for idx, count in enumerate(vulnerability_count)
        if count > 0 or kev_count[idx] > 0
    }
    distance_to_vulnerable = _multi_source_distance(downstream, num_nodes, list(vulnerable_nodes))

    transitive_dependency_count: List[float] = []
    transitive_dependent_count: List[float] = []
    dependency_depth: List[float] = []
    vulnerable_reachability: List[float] = []
    reachable_high_risk: List[float] = []
    vulnerable_neighbor_ratio: List[float] = []

    max_reach_depth = 4
    max_transitive_depth = 6

    for idx in range(num_nodes):
        reach_nodes, reach_depth = _bfs_limited(upstream, idx, max_reach_depth)
        trans_nodes, trans_depth = _bfs_limited(upstream, idx, max_transitive_depth)

        transitive_dependency_count.append(float(len(trans_nodes)))
        dependency_depth.append(float(trans_depth))

        vulnerable_hits = sum(1 for node in reach_nodes if node in vulnerable_nodes)
        high_risk_hits = sum(1 for node in reach_nodes if base_risk[node] >= 0.7)
        vulnerable_reachability.append(float(vulnerable_hits))
        reachable_high_risk.append(float(high_risk_hits))

        neighbors = upstream[idx]
        if neighbors:
            vuln_neighbors = sum(1 for node in neighbors if node in vulnerable_nodes)
            vulnerable_neighbor_ratio.append(float(vuln_neighbors) / float(len(neighbors)))
        else:
            vulnerable_neighbor_ratio.append(0.0)

        transitive_dependent_count.append(float(len(_bfs_limited(downstream, idx, max_transitive_depth)[0])))

    shortest_path_to_vulnerable = [
        float(distance) if distance is not None else 0.0
        for distance in distance_to_vulnerable
    ]

    pagerank = _pagerank(downstream, num_nodes)
    eigenvector = _eigenvector_centrality(undirected, num_nodes)
    closeness = _approx_closeness(undirected, num_nodes)
    betweenness = _approx_betweenness(undirected, num_nodes)

    pagerank = _minmax_scale(pagerank)
    eigenvector = _minmax_scale(eigenvector)
    closeness = _minmax_scale(closeness)
    betweenness = _minmax_scale(betweenness)

    upstream_risk, upstream_depth, upstream_decay = _propagate_risk(
        base_risk,
        downstream,
        iterations=3,
        decay=0.55,
    )
    downstream_risk, _, _ = _propagate_risk(
        base_risk,
        upstream,
        iterations=2,
        decay=0.45,
    )

    vulnerable_transitive_count = list(vulnerable_reachability)
    direct_vs_transitive_ratio = [
        (vulnerability_count[i] + kev_count[i]) / (vulnerable_reachability[i] + 1.0)
        for i in range(num_nodes)
    ]
    historical_vulnerability_density = [
        (vulnerability_count[i] + kev_count[i]) / (transitive_dependency_count[i] + 1.0)
        for i in range(num_nodes)
    ]

    exploit_chain_exposure = [
        _exploit_chain_exposure(
            upstream_risk[i],
            shortest_path_to_vulnerable[i],
            vulnerable_reachability[i],
        )
        for i in range(num_nodes)
    ]

    feature_rows: List[List[float]] = []
    for idx in range(num_nodes):
        feature_rows.append([
            module_rank[idx],
            vulnerability_count[idx],
            kev_count[idx],
            epss_signal[idx],
            cvss_signal[idx],
            in_degree[idx],
            out_degree[idx],
            transitive_dependency_count[idx],
            transitive_dependent_count[idx],
            dependency_depth[idx],
            shortest_path_to_vulnerable[idx],
            vulnerable_reachability[idx],
            reachable_high_risk[idx],
            vulnerable_neighbor_ratio[idx],
            pagerank[idx],
            betweenness[idx],
            eigenvector[idx],
            closeness[idx],
            release_age[idx],
            latest_version_gap[idx],
            maintainer_count[idx],
            update_frequency[idx],
            deprecated_flag[idx],
            archived_flag[idx],
            vulnerable_transitive_count[idx],
            direct_vs_transitive_ratio[idx],
            historical_vulnerability_density[idx],
            recent_cve_count[idx],
            exploit_chain_exposure[idx],
            neighbor_risk_mean[idx],
            neighbor_risk_max[idx],
            upstream_risk[idx],
            downstream_risk[idx],
            float(upstream_depth[idx]),
            upstream_decay[idx],
            runtime_flag[idx],
            optional_flag[idx],
            test_flag[idx],
            critical_path_flag[idx],
            internet_exposed_flag[idx],
        ])

    aux = {
        "base_risk": base_risk,
        "upstream_risk": upstream_risk,
        "upstream_depth": [float(d) for d in upstream_depth],
        "centrality": [
            (pagerank[i] + betweenness[i] + eigenvector[i] + closeness[i]) / 4.0
            for i in range(num_nodes)
        ],
        "reachability": vulnerable_reachability,
        "neighbor_risk": neighbor_risk_mean,
        "cvss_signal": cvss_signal,
        "epss_signal": epss_signal,
        "instability": [
            min(1.0, 0.5 * deprecated_flag[i] + 0.5 * archived_flag[i])
            for i in range(num_nodes)
        ],
    }

    return feature_rows, aux


def _blend_log_epss(max_epss: float, avg_epss: float) -> float:
    return 0.7 * math.log1p(max_epss * 1000.0) + 0.3 * math.log1p(avg_epss * 1000.0)


def _blend_log_cvss(max_cvss: float, avg_cvss: float) -> float:
    return 0.7 * math.log1p(max_cvss) + 0.3 * math.log1p(avg_cvss)


def _base_risk_scores(
    vulnerability_count: List[float],
    kev_count: List[float],
    deprecated_flag: List[float],
    archived_flag: List[float],
) -> List[float]:
    scores: List[float] = []
    for vuln, kev, deprecated, archived in zip(
        vulnerability_count,
        kev_count,
        deprecated_flag,
        archived_flag,
    ):
        vuln_signal = 1.0 if vuln > 0 else 0.0
        kev_signal = 1.0 if kev > 0 else 0.0
        count_signal = min(1.0, math.log1p(vuln) / 3.0)
        instability = min(1.0, 0.5 * deprecated + 0.5 * archived)
        score = 0.5 * vuln_signal + 0.2 * kev_signal + 0.2 * count_signal + 0.1 * instability
        scores.append(min(1.0, score))
    return scores


def _neighbor_risk(neighbors: List[List[int]], base_risk: List[float]) -> Tuple[List[float], List[float]]:
    mean_scores: List[float] = []
    max_scores: List[float] = []
    for idx, deps in enumerate(neighbors):
        if not deps:
            mean_scores.append(0.0)
            max_scores.append(0.0)
            continue
        values = [base_risk[d] for d in deps]
        mean_scores.append(sum(values) / float(len(values)))
        max_scores.append(max(values))
    return mean_scores, max_scores


def _bfs_limited(neighbors: List[List[int]], start: int, max_depth: int) -> Tuple[List[int], int]:
    if max_depth <= 0:
        return [], 0
    visited = {start}
    queue: deque = deque([(start, 0)])
    reachable: List[int] = []
    max_seen = 0
    while queue:
        node, depth = queue.popleft()
        if depth >= max_depth:
            continue
        for nxt in neighbors[node]:
            if nxt in visited:
                continue
            visited.add(nxt)
            reachable.append(nxt)
            queue.append((nxt, depth + 1))
            if depth + 1 > max_seen:
                max_seen = depth + 1
    return reachable, max_seen


def _multi_source_distance(neighbors: List[List[int]], num_nodes: int, sources: List[int]) -> List[Optional[int]]:
    if not sources:
        return [None for _ in range(num_nodes)]
    dist = [None for _ in range(num_nodes)]
    queue: deque = deque()
    for src in sources:
        dist[src] = 0
        queue.append(src)
    while queue:
        node = queue.popleft()
        for nxt in neighbors[node]:
            if dist[nxt] is not None:
                continue
            dist[nxt] = dist[node] + 1
            queue.append(nxt)
    return dist


def _pagerank(neighbors: List[List[int]], num_nodes: int, damping: float = 0.85, iterations: int = 40) -> List[float]:
    if num_nodes == 0:
        return []
    ranks = [1.0 / num_nodes for _ in range(num_nodes)]
    out_degree = [len(neighbors[i]) for i in range(num_nodes)]
    for _ in range(iterations):
        next_ranks = [(1.0 - damping) / num_nodes for _ in range(num_nodes)]
        dangling_sum = sum(ranks[i] for i in range(num_nodes) if out_degree[i] == 0)
        dangling_share = damping * dangling_sum / num_nodes
        for i in range(num_nodes):
            next_ranks[i] += dangling_share
        for i in range(num_nodes):
            if out_degree[i] == 0:
                continue
            share = damping * ranks[i] / out_degree[i]
            for nxt in neighbors[i]:
                next_ranks[nxt] += share
        ranks = next_ranks
    return ranks


def _eigenvector_centrality(neighbors: List[List[int]], num_nodes: int, iterations: int = 40) -> List[float]:
    if num_nodes == 0:
        return []
    scores = [1.0 / num_nodes for _ in range(num_nodes)]
    for _ in range(iterations):
        next_scores = [0.0 for _ in range(num_nodes)]
        for i in range(num_nodes):
            for nxt in neighbors[i]:
                next_scores[nxt] += scores[i]
        norm = math.sqrt(sum(value * value for value in next_scores)) or 1.0
        scores = [value / norm for value in next_scores]
    return scores


def _approx_closeness(neighbors: List[List[int]], num_nodes: int, samples: int = 64) -> List[float]:
    if num_nodes == 0:
        return []
    sample_count = min(samples, num_nodes)
    sampled = random.sample(range(num_nodes), sample_count)
    distance_sum = [0.0 for _ in range(num_nodes)]
    reachable_count = [0 for _ in range(num_nodes)]

    for src in sampled:
        dist = [-1 for _ in range(num_nodes)]
        dist[src] = 0
        queue: deque = deque([src])
        while queue:
            node = queue.popleft()
            for nxt in neighbors[node]:
                if dist[nxt] >= 0:
                    continue
                dist[nxt] = dist[node] + 1
                queue.append(nxt)
        for idx, value in enumerate(dist):
            if value > 0:
                distance_sum[idx] += float(value)
                reachable_count[idx] += 1

    closeness = []
    for idx in range(num_nodes):
        if distance_sum[idx] <= 0:
            closeness.append(0.0)
        else:
            closeness.append(float(reachable_count[idx]) / distance_sum[idx])
    return closeness


def _approx_betweenness(neighbors: List[List[int]], num_nodes: int, samples: int = 64) -> List[float]:
    if num_nodes == 0:
        return []
    sample_count = min(samples, num_nodes)
    sampled = random.sample(range(num_nodes), sample_count)
    betweenness = [0.0 for _ in range(num_nodes)]

    for s in sampled:
        stack: List[int] = []
        pred: List[List[int]] = [[] for _ in range(num_nodes)]
        sigma = [0.0 for _ in range(num_nodes)]
        sigma[s] = 1.0
        dist = [-1 for _ in range(num_nodes)]
        dist[s] = 0
        queue: deque = deque([s])

        while queue:
            v = queue.popleft()
            stack.append(v)
            for w in neighbors[v]:
                if dist[w] < 0:
                    dist[w] = dist[v] + 1
                    queue.append(w)
                if dist[w] == dist[v] + 1:
                    sigma[w] += sigma[v]
                    pred[w].append(v)

        delta = [0.0 for _ in range(num_nodes)]
        while stack:
            w = stack.pop()
            for v in pred[w]:
                if sigma[w] > 0:
                    delta[v] += (sigma[v] / sigma[w]) * (1.0 + delta[w])
            if w != s:
                betweenness[w] += delta[w]

    scale = 1.0 / max(1.0, float(sample_count))
    return [value * scale for value in betweenness]


def _propagate_risk(
    base_risk: List[float],
    neighbors: List[List[int]],
    iterations: int,
    decay: float,
    epsilon: float = 0.01,
) -> Tuple[List[float], List[int], List[float]]:
    num_nodes = len(base_risk)
    risk = list(base_risk)
    depth = [0 for _ in range(num_nodes)]
    decay_score = [0.0 for _ in range(num_nodes)]

    for step in range(1, iterations + 1):
        next_risk = list(base_risk)
        for idx in range(num_nodes):
            deps = neighbors[idx]
            if not deps:
                continue
            agg = sum(risk[d] for d in deps) / float(len(deps))
            contribution = decay * agg
            next_risk[idx] = min(1.0, next_risk[idx] + contribution)
            if contribution > epsilon:
                depth[idx] = step
                decay_score[idx] += contribution
        risk = next_risk

    return risk, depth, decay_score


def _exploit_chain_exposure(upstream_risk: float, shortest_path: float, reachability: float) -> float:
    if shortest_path <= 0:
        path_factor = 0.0
    else:
        path_factor = 1.0 / (1.0 + shortest_path)
    return min(1.0, upstream_risk * path_factor * math.log1p(reachability + 1.0))


def _minmax_scale(values: List[float]) -> List[float]:
    if not values:
        return []
    min_val = min(values)
    max_val = max(values)
    if max_val <= min_val:
        return [0.0 for _ in values]
    return [(value - min_val) / (max_val - min_val) for value in values]


def _apply_transforms(features: List[List[float]], feature_order: List[str]) -> List[List[float]]:
    transformed: List[List[float]] = []
    for row in features:
        updated = []
        for idx, value in enumerate(row):
            name = feature_order[idx]
            if name == "moduleRank":
                updated.append(math.log1p(value * 1e6))
            elif name in LOG1P_FEATURES:
                updated.append(math.log1p(max(0.0, value)))
            else:
                updated.append(value)
        transformed.append(updated)
    return transformed


def _log_feature_diagnostics(features: List[List[float]], feature_order: List[str]) -> None:
    if not features:
        return
    tensor = torch.tensor(features, dtype=torch.float)
    mean = tensor.mean(dim=0)
    std = tensor.std(dim=0)
    var = tensor.var(dim=0)
    min_val = tensor.min(dim=0).values
    max_val = tensor.max(dim=0).values
    sparsity = (tensor == 0.0).to(torch.float).mean(dim=0)

    for idx, name in enumerate(feature_order):
        logger.info(
            "Feature %s: mean=%.4f std=%.4f var=%.4f min=%.4f max=%.4f sparsity=%.1f%%",
            name,
            mean[idx].item(),
            std[idx].item(),
            var[idx].item(),
            min_val[idx].item(),
            max_val[idx].item(),
            sparsity[idx].item() * 100.0,
        )
        if var[idx].item() < 1e-6:
            logger.warning("Feature variance near zero: %s", name)
        if sparsity[idx].item() > 0.95:
            logger.warning("Feature sparsity above 95%%: %s", name)

    _log_correlation(tensor, feature_order)


def _align_features(
    features: List[List[float]],
    current_order: List[str],
    expected_order: List[str],
) -> List[List[float]]:
    if not features:
        return features

    index_map = {name: idx for idx, name in enumerate(current_order)}
    aligned: List[List[float]] = []
    for row in features:
        aligned.append([
            row[index_map[name]] if name in index_map else 0.0
            for name in expected_order
        ])
    return aligned


def _prune_features(
    features: List[List[float]],
    feature_order: List[str],
) -> Tuple[List[List[float]], List[str], List[str]]:
    if not features:
        return features, feature_order, []

    tensor = torch.tensor(features, dtype=torch.float)
    var = tensor.var(dim=0)
    sparsity = (tensor == 0.0).to(torch.float).mean(dim=0)

    drop_indices: List[int] = []
    dropped_names: List[str] = []
    for idx, name in enumerate(feature_order):
        if name in DROP_FEATURES:
            drop_indices.append(idx)
            dropped_names.append(name)
            continue
        if var[idx].item() <= 1e-12 or sparsity[idx].item() >= 0.999999:
            drop_indices.append(idx)
            dropped_names.append(name)
            continue
        if name in COLLINEARITY_DROPS:
            drop_indices.append(idx)
            dropped_names.append(name)

    keep_indices = [
        idx for idx in range(len(feature_order))
        if idx not in drop_indices
    ]
    new_order = [feature_order[idx] for idx in keep_indices]
    pruned = [[row[idx] for idx in keep_indices] for row in features]

    return pruned, new_order, dropped_names


def _log_correlation(tensor: torch.Tensor, feature_order: List[str]) -> None:
    if tensor.size(0) < 2:
        return
    centered = tensor - tensor.mean(dim=0)
    denom = tensor.std(dim=0) + 1e-8
    normed = centered / denom
    corr = (normed.T @ normed) / max(1.0, float(tensor.size(0) - 1))

    warnings = []
    for i in range(corr.size(0)):
        for j in range(i + 1, corr.size(1)):
            value = corr[i, j].item()
            if abs(value) >= 0.95:
                warnings.append((abs(value), i, j, value))

    warnings.sort(reverse=True)
    if warnings:
        logger.warning("High feature collinearity detected (|corr| >= 0.95)")
        for _, i, j, value in warnings[:10]:
            logger.warning(
                "Collinearity: %s vs %s corr=%.3f",
                feature_order[i],
                feature_order[j],
                value,
            )


def _build_labels(features: List[List[float]], aux: Dict[str, List[float]], nodes: List[Dict]) -> torch.Tensor:
    scores: List[float] = []
    upstream = aux.get("upstream_risk", [])
    centrality = aux.get("centrality", [])
    reachability = aux.get("reachability", [])
    neighbor_risk = aux.get("neighbor_risk", [])
    instability = aux.get("instability", [])
    cvss_signal = aux.get("cvss_signal", [])
    epss_signal = aux.get("epss_signal", [])

    max_reach = max(reachability) if reachability else 1.0
    max_neighbor = max(neighbor_risk) if neighbor_risk else 1.0

    for idx in range(len(features)):
        reach_score = reachability[idx] / max(1.0, max_reach)
        neighbor_score = neighbor_risk[idx] / max(1.0, max_neighbor)
        heuristic_hint = 0.0
        if idx < len(cvss_signal):
            heuristic_hint += 0.05 * cvss_signal[idx]
        if idx < len(epss_signal):
            heuristic_hint += 0.05 * epss_signal[idx]

        score = (
            0.30 * upstream[idx]
            + 0.20 * aux.get("base_risk", [0.0])[idx]
            + 0.15 * centrality[idx]
            + 0.15 * reach_score
            + 0.10 * neighbor_score
            + 0.10 * instability[idx]
            + heuristic_hint
        )
        scores.append(score)

    labels = torch.zeros(len(scores), dtype=torch.long)
    if not scores:
        return labels

    total = len(scores)
    high_target = max(1, int(round(total * 0.10)))
    medium_target = max(1, int(round(total * 0.20)))

    ranked = sorted(range(total), key=lambda i: scores[i], reverse=True)
    for idx in ranked[:high_target]:
        labels[idx] = 2
    for idx in ranked[high_target:high_target + medium_target]:
        labels[idx] = 1

    low_count = int((labels == 0).sum().item())
    medium_count = int((labels == 1).sum().item())
    high_count = int((labels == 2).sum().item())

    logger.info(
        "Label distribution: LOW=%s (%.1f%%) MEDIUM=%s (%.1f%%) HIGH=%s (%.1f%%)",
        low_count, (low_count / max(1, total)) * 100.0,
        medium_count, (medium_count / max(1, total)) * 100.0,
        high_count, (high_count / max(1, total)) * 100.0,
    )

    top = ranked[:20]
    for idx in top:
        name = nodes[idx].get("packageName") if idx < len(nodes) else f"node-{idx}"
        logger.info("Top score: package=%s score=%.3f label=%s", name, scores[idx], LABELS[int(labels[idx])])

    return labels
