import argparse
import json
import logging
from pathlib import Path
from typing import Tuple

import torch
from torch import nn
from sklearn.metrics import confusion_matrix, precision_recall_fscore_support
from torch_geometric.data import Data

from data.graph_loader import load_graph
from data.zenodo_loader import load_zenodo_dataset
from models.gnn import GnnClassifier
from models.gat import GatClassifier
from utils.logging import setup_logging
from utils.metrics import accuracy, macro_f1
from utils.sampling import sample_train_indices
from utils.seed import set_seed

logger = logging.getLogger(__name__)


def split_masks(num_nodes: int, train_ratio: float, seed: int) -> Tuple[torch.Tensor, torch.Tensor]:
    generator = torch.Generator().manual_seed(seed)
    perm = torch.randperm(num_nodes, generator=generator)
    train_size = int(num_nodes * train_ratio)
    train_idx = perm[:train_size]
    test_idx = perm[train_size:]

    train_mask = torch.zeros(num_nodes, dtype=torch.bool)
    test_mask = torch.zeros(num_nodes, dtype=torch.bool)
    train_mask[train_idx] = True
    test_mask[test_idx] = True
    return train_mask, test_mask


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


def evaluate(model: nn.Module, data: Data, num_classes: int) -> Tuple[float, float]:
    model.eval()
    with torch.no_grad():
        out = model(data.x, data.edge_index)
        pred = out.argmax(dim=1)
        pred_test = pred[data.test_mask]
        target_test = data.y[data.test_mask]
        return accuracy(pred_test, target_test), macro_f1(pred_test, target_test, num_classes)


def main() -> None:
    parser = argparse.ArgumentParser(description="Train an experimental GNN for SBOM threat analysis.")
    parser.add_argument("--data", required=True, help="Path to exported graph JSON or PyG .pt file.")
    parser.add_argument(
        "--dataset-format",
        choices=["spring-export", "zenodo"],
        default="spring-export",
        help="spring-export = JSON from Spring Boot GraphExportController; "
             "zenodo = PyG Data built by ml-zenodo-a/data/build_gnn_dataset.py.",
    )
    parser.add_argument("--model", choices=["gcn", "gat"], default="gcn", help="Model architecture.")
    parser.add_argument("--epochs", type=int, default=50, help="Number of training epochs.")
    parser.add_argument("--hidden", type=int, default=32, help="Hidden dimension size.")
    parser.add_argument("--heads", type=int, default=4, help="Attention heads for GAT.")
    parser.add_argument("--dropout", type=float, default=0.2, help="Dropout for GNN layers.")
    parser.add_argument("--lr", type=float, default=1e-3, help="Learning rate.")
    parser.add_argument("--train-ratio", type=float, default=0.8, help="Train/test split ratio.")
    parser.add_argument("--seed", type=int, default=42, help="Random seed for reproducibility.")
    parser.add_argument("--model-out", default="", help="Model output path (optional).")
    parser.add_argument(
        "--class-weights",
        type=float,
        nargs=3,
        default=None,
        metavar=("LOW", "MEDIUM", "HIGH"),
        help="Optional class weights (low medium high).",
    )
    args = parser.parse_args()

    setup_logging()
    set_seed(args.seed)

    # Message passing lets neighbor signals influence node representations.
    if args.dataset_format == "zenodo":
        logger.info("Loading Zenodo-format dataset: %s", args.data)
        data, labels = load_zenodo_dataset(args.data)
    else:
        data, labels = load_graph(args.data)

    class_counts = torch.bincount(data.y, minlength=len(labels)).to(torch.float)
    total = int(class_counts.sum().item())
    dist = (class_counts / max(1.0, float(total))) * 100.0
    logger.info(
        "Class distribution: LOW=%s (%.1f%%), MEDIUM=%s (%.1f%%), HIGH=%s (%.1f%%)",
        int(class_counts[0].item()), dist[0].item(),
        int(class_counts[1].item()), dist[1].item(),
        int(class_counts[2].item()), dist[2].item(),
    )
    max_share = (class_counts.max().item() / max(1.0, float(total)))
    if max_share >= 0.90:
        logger.warning("Class imbalance detected: largest class is %.1f%%", max_share * 100.0)

    high_ratio = (class_counts[2].item() / max(1.0, float(total)))
    medium_ratio = (class_counts[1].item() / max(1.0, float(total)))
    if high_ratio < 0.02:
        logger.warning("Class distribution warning: HIGH below 2%% (%.2f%%)", high_ratio * 100.0)
    if medium_ratio < 0.05:
        logger.warning("Class distribution warning: MEDIUM below 5%% (%.2f%%)", medium_ratio * 100.0)

    data.train_mask, data.test_mask = split_masks(data.num_nodes, args.train_ratio, args.seed)

    # Baseline GCN vs attention-based GAT.
    model_registry = {
        "gcn": lambda: GnnClassifier(
            input_dim=data.num_node_features,
            hidden_dim=args.hidden,
            num_classes=len(labels),
            dropout=args.dropout,
        ),
        "gat": lambda: GatClassifier(
            input_dim=data.num_node_features,
            hidden_dim=args.hidden,
            num_classes=len(labels),
            heads=args.heads,
            dropout=args.dropout,
        ),
    }

    model_key = args.model.lower()
    if model_key not in model_registry:
        raise ValueError(f"Unsupported model: {args.model}")

    logger.info("Using model: %s", model_key.upper())
    model = model_registry[model_key]()
    optimizer = torch.optim.Adam(model.parameters(), lr=args.lr)

    if args.class_weights:
        raw_weights = torch.tensor(args.class_weights, dtype=torch.float)
    else:
        class_distribution = torch.tensor([0.7, 0.2, 0.1], dtype=torch.float)
        raw_weights = 1.0 / class_distribution

    class_weights = raw_weights / raw_weights.mean()
    loss_fn = nn.CrossEntropyLoss(weight=class_weights)

    if args.model_out:
        model_path = Path(args.model_out)
    else:
        model_path = Path(f"exports/{model_key}_model.pt")

    best_f1 = -1.0
    no_improve = 0
    patience = 10

    for epoch in range(1, args.epochs + 1):
        sample_indices = sample_train_indices(
            data.y,
            data.train_mask,
            feature_names=getattr(data, "feature_names", None),
            raw_features=getattr(data, "raw_features", None),
            seed=args.seed + epoch,
        )
        loss = train_epoch(model, data, optimizer, loss_fn, sample_indices)
        acc, f1 = evaluate(model, data, len(labels))
        if epoch % 10 == 0 or epoch == args.epochs:
            logger.info("Epoch %s/%s - loss=%.4f acc=%.3f f1=%.3f", epoch, args.epochs, loss, acc, f1)

        if f1 > best_f1:
            best_f1 = f1
            no_improve = 0
            model_path.parent.mkdir(parents=True, exist_ok=True)
            checkpoint = {
                "model_state": model.state_dict(),
                "labels": labels,
                "input_dim": data.num_node_features,
                "hidden_dim": args.hidden,
                "model": model_key,
                "feature_names": getattr(data, "feature_names", None),
                "best_f1": best_f1,
                "epoch": epoch,
            }
            torch.save(checkpoint, model_path)
            meta_path = model_path.with_suffix(model_path.suffix + ".meta.json")
            with meta_path.open("w", encoding="utf-8") as handle:
                json.dump(
                    {
                        "feature_names": checkpoint.get("feature_names"),
                        "input_dim": checkpoint.get("input_dim"),
                        "model": checkpoint.get("model"),
                        "hidden_dim": checkpoint.get("hidden_dim"),
                    },
                    handle,
                    indent=2,
                )
            logger.info("New best checkpoint saved: epoch=%s f1=%.3f", epoch, best_f1)
        else:
            no_improve += 1
            if no_improve >= patience:
                logger.info("Early stopping at epoch %s (best f1=%.3f)", epoch, best_f1)
                break

    acc, f1 = evaluate(model, data, len(labels))
    logger.info("Final metrics - acc=%.3f f1=%.3f", acc, f1)

    with torch.no_grad():
        logits = model(data.x, data.edge_index)
        pred = logits.argmax(dim=1)
        pred_test = pred[data.test_mask].cpu().numpy()
        target_test = data.y[data.test_mask].cpu().numpy()

    precision, recall, f1_per_class, _ = precision_recall_fscore_support(
        target_test,
        pred_test,
        labels=list(range(len(labels))),
        average=None,
        zero_division=0,
    )
    macro_precision, macro_recall, macro_f1, _ = precision_recall_fscore_support(
        target_test,
        pred_test,
        labels=list(range(len(labels))),
        average="macro",
        zero_division=0,
    )
    matrix = confusion_matrix(target_test, pred_test, labels=list(range(len(labels))))

    logger.info("Macro precision=%.3f recall=%.3f f1=%.3f", macro_precision, macro_recall, macro_f1)
    logger.info("Per-class F1: LOW=%.3f MEDIUM=%.3f HIGH=%.3f", f1_per_class[0], f1_per_class[1], f1_per_class[2])
    logger.info("Confusion matrix: %s", matrix.tolist())

    if model_path.exists():
        logger.info("Best model saved to %s", model_path)


if __name__ == "__main__":
    main()
