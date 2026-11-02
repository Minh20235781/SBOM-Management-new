from typing import List

import torch
from torch import nn
from torch_geometric.nn import GATConv


class GatClassifier(nn.Module):
    """GAT classifier for node-level risk labels."""

    def __init__(
        self,
        input_dim: int,
        hidden_dim: int,
        num_classes: int,
        heads: int = 4,
        dropout: float = 0.2,
    ) -> None:
        super().__init__()
        self.dropout = nn.Dropout(dropout)

        # Attention layers.
        self.gat1 = GATConv(
            in_channels=input_dim,
            out_channels=hidden_dim,
            heads=heads,
            dropout=dropout,
            concat=True,
        )

        self.gat2 = GATConv(
            in_channels=hidden_dim * heads,
            out_channels=num_classes,
            heads=1,
            dropout=dropout,
            concat=False,
        )

    def forward(self, x: torch.Tensor, edge_index: torch.Tensor) -> torch.Tensor:
        """Forward pass."""
        x = self.gat1(x, edge_index)
        x = torch.relu(x)
        x = self.dropout(x)
        x = self.gat2(x, edge_index)
        return x

    def predict(self, x: torch.Tensor, edge_index: torch.Tensor) -> torch.Tensor:
        """Return predicted class indices for each node."""
        logits = self.forward(x, edge_index)
        return logits.argmax(dim=1)

    def predict_proba(self, x: torch.Tensor, edge_index: torch.Tensor) -> torch.Tensor:
        """Return class probabilities for each node (low/medium/high)."""
        logits = self.forward(x, edge_index)
        return torch.softmax(logits, dim=1)
