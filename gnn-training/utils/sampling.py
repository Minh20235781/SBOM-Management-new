from typing import List, Optional

import torch
from torch.utils.data import WeightedRandomSampler


def compute_class_weights(labels: torch.Tensor, num_classes: int) -> torch.Tensor:
    counts = torch.bincount(labels, minlength=num_classes).to(torch.float)
    total = counts.sum().item()
    weights = []
    for count in counts.tolist():
        if count <= 0:
            weights.append(0.0)
        else:
            weights.append(float(total) / (num_classes * float(count)))
    return torch.tensor(weights, dtype=torch.float)


def sample_train_indices(
    labels: torch.Tensor,
    train_mask: torch.Tensor,
    feature_names: Optional[List[str]] = None,
    raw_features: Optional[torch.Tensor] = None,
    seed: int = 0,
    hard_negative_boost: float = 2.5,
) -> torch.Tensor:
    train_idx = torch.where(train_mask)[0]
    if train_idx.numel() == 0:
        return train_idx

    num_classes = int(labels.max().item()) + 1
    class_weights = compute_class_weights(labels[train_idx], num_classes)
    sample_weights = class_weights[labels[train_idx]]

    if feature_names and raw_features is not None and raw_features.numel() > 0:
        name_to_idx = {name: idx for idx, name in enumerate(feature_names)}
        risk_idx = name_to_idx.get("upstreamRiskScore")
        reach_idx = name_to_idx.get("vulnerableReachability")
        if risk_idx is not None or reach_idx is not None:
            risk_signal = torch.zeros(train_idx.size(0), dtype=torch.float)
            if risk_idx is not None:
                risk_signal += raw_features[train_idx, risk_idx]
            if reach_idx is not None:
                risk_signal += raw_features[train_idx, reach_idx]

            low_mask = labels[train_idx] == 0
            if low_mask.any():
                low_scores = risk_signal[low_mask]
                threshold = torch.quantile(low_scores, 0.8) if low_scores.numel() > 4 else low_scores.max()
                hard_negatives = low_mask & (risk_signal >= threshold)
                sample_weights[hard_negatives] *= hard_negative_boost

    generator = torch.Generator()
    generator.manual_seed(seed)
    sampler = WeightedRandomSampler(
        weights=sample_weights,
        num_samples=train_idx.numel(),
        replacement=True,
        generator=generator,
    )
    sampled = torch.tensor(list(sampler), dtype=torch.long)
    return train_idx[sampled]
