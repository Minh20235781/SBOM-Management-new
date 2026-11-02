import argparse
import logging
from typing import Dict

import torch
from torch import nn
from torch_geometric.data import Data

from data.graph_loader import load_graph
from models.gat import GatClassifier
from models.gnn import GnnClassifier
from utils.logging import setup_logging
from utils.losses import FocalLoss
from utils.metrics import accuracy, macro_f1
from utils.sampling import compute_class_weights, sample_train_indices
from utils.seed import set_seed

logger = logging.getLogger(__name__)


def split_masks(num_nodes: int, train_ratio: float, seed: int) -> Dict[str, torch.Tensor]:
    generator = torch.Generator().manual_seed(seed)
    perm = torch.randperm(num_nodes, generator=generator)
    train_size = int(num_nodes * train_ratio)
    train_idx = perm[:train_size]
    test_idx = perm[train_size:]

    train_mask = torch.zeros(num_nodes, dtype=torch.bool)
    test_mask = torch.zeros(num_nodes, dtype=torch.bool)
    train_mask[train_idx] = True
    test_mask[test_idx] = True
    return {"train": train_mask, "test": test_mask}


def train_epoch(
    model: nn.Module,
    data: Data,
    optimizer: torch.optim.Optimizer,
    loss_fn: nn.Module,
    sample_indices: torch.Tensor,
) -> float:
    model.train()
    optimizer.zero_grad()

    out = model(data.x, data.edge_index)
    loss = loss_fn(out[sample_indices], data.y[sample_indices])
    loss.backward()
    optimizer.step()
    return float(loss.item())


def evaluate(model: nn.Module, data: Data, num_classes: int) -> Dict[str, float]:
    model.eval()
    with torch.no_grad():
        out = model(data.x, data.edge_index)
        pred = out.argmax(dim=1)
        pred_test = pred[data.test_mask]
        target_test = data.y[data.test_mask]
        return {
            "acc": accuracy(pred_test, target_test),
            "f1": macro_f1(pred_test, target_test, num_classes),
        }


def train_and_eval(model: nn.Module, data: Data, epochs: int, lr: float, seed: int) -> Dict[str, float]:
    optimizer = torch.optim.Adam(model.parameters(), lr=lr)
    class_weights = compute_class_weights(data.y[data.train_mask], int(data.y.max().item()) + 1)
    loss_fn = FocalLoss(weight=class_weights, gamma=2.0)
    for _ in range(epochs):
        sample_indices = sample_train_indices(
            data.y,
            data.train_mask,
            feature_names=getattr(data, "feature_names", None),
            raw_features=getattr(data, "raw_features", None),
            seed=seed,
        )
        train_epoch(model, data, optimizer, loss_fn, sample_indices)
    return evaluate(model, data, int(data.y.max().item()) + 1)


def main() -> None:
    parser = argparse.ArgumentParser(description="Compare GCN vs GAT on one export.")
    parser.add_argument("--data", required=True, help="Path to exported graph JSON file.")
    parser.add_argument("--epochs", type=int, default=30, help="Training epochs per model.")
    parser.add_argument("--hidden", type=int, default=32, help="Hidden dimension size.")
    parser.add_argument("--heads", type=int, default=4, help="Attention heads for GAT.")
    parser.add_argument("--dropout", type=float, default=0.2, help="Dropout for GNN layers.")
    parser.add_argument("--lr", type=float, default=1e-3, help="Learning rate.")
    parser.add_argument("--train-ratio", type=float, default=0.8, help="Train/test split ratio.")
    parser.add_argument("--seed", type=int, default=42, help="Random seed for reproducibility.")
    args = parser.parse_args()

    setup_logging()
    set_seed(args.seed)

    data, labels = load_graph(args.data)
    masks = split_masks(data.num_nodes, args.train_ratio, args.seed)
    data.train_mask = masks["train"]
    data.test_mask = masks["test"]

    logger.info("Running baseline comparison on %s nodes", data.num_nodes)

    gcn = GnnClassifier(
        input_dim=data.num_node_features,
        hidden_dim=args.hidden,
        num_classes=len(labels),
        dropout=args.dropout,
    )
    gcn_metrics = train_and_eval(gcn, data, args.epochs, args.lr, args.seed)
    logger.info("GCN metrics - acc=%.3f f1=%.3f", gcn_metrics["acc"], gcn_metrics["f1"])

    gat = GatClassifier(
        input_dim=data.num_node_features,
        hidden_dim=args.hidden,
        num_classes=len(labels),
        heads=args.heads,
        dropout=args.dropout,
    )
    gat_metrics = train_and_eval(gat, data, args.epochs, args.lr, args.seed)
    logger.info("GAT metrics - acc=%.3f f1=%.3f", gat_metrics["acc"], gat_metrics["f1"])


if __name__ == "__main__":
    main()
