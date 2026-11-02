from typing import Tuple

import torch


def accuracy(pred: torch.Tensor, target: torch.Tensor) -> float:
    if pred.numel() == 0:
        return 0.0
    return float((pred == target).sum().item() / pred.numel())


def macro_f1(pred: torch.Tensor, target: torch.Tensor, num_classes: int) -> float:
    if pred.numel() == 0:
        return 0.0

    f1_sum = 0.0
    for cls in range(num_classes):
        tp = ((pred == cls) & (target == cls)).sum().item()
        fp = ((pred == cls) & (target != cls)).sum().item()
        fn = ((pred != cls) & (target == cls)).sum().item()

        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0.0
        f1_sum += f1

    return f1_sum / num_classes
