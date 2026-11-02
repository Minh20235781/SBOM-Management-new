from typing import Tuple

import torch
from torch import nn
from torch_geometric.nn import GCNConv


class GnnClassifier(nn.Module):
    """
    Simple GCN-based classifier for node-level risk labels.
    """

    def __init__(self, input_dim: int, hidden_dim: int, num_classes: int, dropout: float = 0.2) -> None:
        super().__init__()
        self.conv1 = GCNConv(input_dim, hidden_dim)
        self.conv2 = GCNConv(hidden_dim, num_classes)
        self.dropout = nn.Dropout(dropout)

    def forward(self, x: torch.Tensor, edge_index: torch.Tensor) -> torch.Tensor:
        x = self.conv1(x, edge_index).relu()
        x = self.dropout(x)
        x = self.conv2(x, edge_index)
        return x
