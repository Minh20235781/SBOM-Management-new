# GNN Training (Experimental)

This folder hosts an isolated, Python-only GNN training pipeline for SBOM research.
It is independent from the Spring Boot services and consumes exported graph JSON.

## Quick Start

```bash
pip install torch torch_geometric
python training/train.py --data ../demo/exports/gnn/gnn-export-<timestamp>.json
```

## GAT Example

```bash
python training/train.py --data ../demo/exports/gnn/gnn-export-<timestamp>.json --model gat --heads 4
```

## Model Comparison

Run both GCN and GAT on the same export for a quick baseline comparison.

```bash
python training/compare_models.py --data ../demo/exports/gnn/gnn-export-<timestamp>.json
```

## Notes

- Graph neural networks use message passing, so edges matter as much as node features.
- This pipeline is intentionally experimental and does not affect production flows.
