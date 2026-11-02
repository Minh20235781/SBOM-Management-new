from typing import Optional

import torch
from torch import nn


class FocalLoss(nn.Module):
    """Focal loss for imbalanced classification."""

    def __init__(self, weight: Optional[torch.Tensor] = None, gamma: float = 2.0) -> None:
        super().__init__()
        self.weight = weight
        self.gamma = gamma

    def forward(self, logits: torch.Tensor, target: torch.Tensor) -> torch.Tensor:
        if logits.numel() == 0:
            return torch.tensor(0.0, device=logits.device)

        log_probs = torch.log_softmax(logits, dim=1)
        probs = torch.exp(log_probs)

        target = target.long()
        idx = torch.arange(target.size(0), device=logits.device)
        target_logp = log_probs[idx, target]
        target_prob = probs[idx, target]

        if self.weight is not None:
            alpha = self.weight.to(logits.device)[target]
        else:
            alpha = 1.0

        loss = -alpha * (1.0 - target_prob) ** self.gamma * target_logp
        return loss.mean()
