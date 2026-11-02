"""Loader for the Zenodo-format PyG dataset built by
``ml-zenodo-a/data/build_gnn_dataset.py``.

Mirrors the shape of ``data.graph_loader.load_graph`` so ``train.py`` can
swap between the Spring Boot JSON export and the Zenodo-built artifact
without further changes.
"""

from __future__ import annotations

import logging
from typing import List, Tuple

import torch
from torch_geometric.data import Data

logger = logging.getLogger(__name__)

LABELS = ["low", "medium", "high"]


def load_zenodo_dataset(path: str) -> Tuple[Data, List[str]]:
    """Load a Zenodo-built PyG Data object and return ``(data, LABELS)``.

    The build script already attached ``train_mask`` / ``test_mask`` and
    ``feature_names`` to the Data. ``train.py`` expects those names on
    ``data`` rather than reconstructed here.
    """
    data: Data = torch.load(path, weights_only=False)

    expected = {"x", "edge_index", "y", "train_mask", "test_mask"}
    missing = expected - set(data.keys()) if hasattr(data, "keys") else expected - data.to_dict().keys()
    if missing:
        raise ValueError(f"Zenodo dataset missing required fields: {sorted(missing)}")

    if not hasattr(data, "feature_names") or data.feature_names is None:
        data.feature_names = [
            "advisory_count",
            "critical_count",
            "high_count",
            "medium_count",
            "low_count",
            "max_advisory_year",
            "rank_score",
            "ecosystem_npm",
            "ecosystem_Maven",
            "ecosystem_PyPI",
            "ecosystem_Packagist",
            "ecosystem_RubyGems",
            "ecosystem_Other",
        ]

    data.raw_features = data.x  # sampling diagnostic in train.py

    num_classes = int(getattr(data, "num_classes", 3))
    labels = LABELS[:num_classes]

    logger.info(
        "Loaded Zenodo dataset: nodes=%d edges=%d features=%d classes=%d",
        data.num_nodes,
        data.num_edges,
        data.num_node_features,
        num_classes,
    )
    return data, labels
