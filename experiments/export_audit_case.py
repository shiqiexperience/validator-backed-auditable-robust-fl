"""Export an audit-chain case study from one robust benchmark run."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
from pathlib import Path

import matplotlib.pyplot as plt
import pandas as pd


def verify_chain(path: Path) -> tuple[bool, list[dict]]:
    blocks: list[dict] = []
    previous = "0" * 64
    ok = True
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            block = json.loads(line)
            if block.get("previous_hash") != previous:
                ok = False
            # The benchmark stores a lightweight demonstrative hash chain. Verify linkage,
            # and preserve the stored hash for reporting without reserializing payloads.
            previous = block.get("hash", "")
            blocks.append(block)
    return ok, blocks


def write_csv(path: Path, rows: list[dict], fieldnames: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def style() -> None:
    plt.rcParams.update(
        {
            "font.family": "Arial",
            "font.size": 9,
            "axes.titlesize": 11,
            "axes.labelsize": 9,
            "legend.fontsize": 8,
            "xtick.labelsize": 8,
            "ytick.labelsize": 8,
            "figure.dpi": 160,
            "savefig.dpi": 300,
            "axes.spines.top": False,
            "axes.spines.right": False,
            "axes.grid": True,
            "grid.alpha": 0.24,
            "grid.linewidth": 0.6,
        }
    )


def save(fig: plt.Figure, out_dir: Path, name: str) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    fig.tight_layout()
    fig.savefig(out_dir / f"{name}.png", bbox_inches="tight")
    fig.savefig(out_dir / f"{name}.pdf", bbox_inches="tight")
    plt.close(fig)


def plot_round_metrics(metrics: pd.DataFrame, out_dir: Path) -> None:
    fig, axes = plt.subplots(1, 2, figsize=(9, 3.4))
    axes[0].plot(metrics["round"], metrics["clean_accuracy"], color="#2563eb", linewidth=1.8, label="Clean accuracy")
    axes[0].plot(metrics["round"], metrics["backdoor_asr"], color="#dc2626", linewidth=1.4, label="ASR")
    axes[0].set_xlabel("Round")
    axes[0].set_ylabel("Percentage (%)")
    axes[0].set_title("Model Utility and Attack Success")
    axes[0].legend(frameon=False)

    axes[1].plot(metrics["round"], metrics["zero_weight_rate"], color="#16a34a", linewidth=1.8, label="Zero-weight rate")
    axes[1].plot(metrics["round"], metrics["hard_rejection_rate"], color="#7c3aed", linewidth=1.4, label="Hard rejection rate")
    axes[1].plot(metrics["round"], metrics["mean_aggregation_weight"] * 100, color="#111827", linewidth=1.2, label="Mean weight x100")
    axes[1].set_xlabel("Round")
    axes[1].set_ylabel("Rate / scaled weight")
    axes[1].set_title("Aggregation Decisions")
    axes[1].legend(frameon=False)
    save(fig, out_dir, "audit_case_round_metrics")


def plot_client_weights(clients: pd.DataFrame, out_dir: Path) -> None:
    fig, ax = plt.subplots(figsize=(8.6, 3.8))
    for client_id, group in clients.groupby("client_id"):
        is_mal = int(group["is_malicious"].iloc[0]) == 1
        color = "#dc2626" if is_mal else "#2563eb"
        alpha = 0.95 if is_mal else 0.35
        linewidth = 1.7 if is_mal else 0.9
        ax.plot(group["round"], group["aggregation_weight"], color=color, alpha=alpha, linewidth=linewidth)
    ax.set_xlabel("Round")
    ax.set_ylabel("Aggregation weight")
    ax.set_title("Per-Client Aggregation Weights")
    ax.plot([], [], color="#dc2626", linewidth=1.7, label="Malicious clients")
    ax.plot([], [], color="#2563eb", linewidth=1.2, alpha=0.6, label="Benign clients")
    ax.legend(frameon=False)
    save(fig, out_dir, "audit_case_client_weights")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--run-dir", required=True)
    parser.add_argument("--out-dir", default="experiments_b_journal/audit_case")
    args = parser.parse_args()

    run_dir = Path(args.run_dir)
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    style()

    metrics = pd.read_csv(run_dir / "metrics_round.csv")
    clients = pd.read_csv(run_dir / "client_round_metrics.csv")
    config = json.loads((run_dir / "config.json").read_text(encoding="utf-8"))
    summary = json.loads((run_dir / "summary.json").read_text(encoding="utf-8"))
    chain_ok, blocks = verify_chain(run_dir / "audit_chain.jsonl")

    plot_round_metrics(metrics, out_dir)
    plot_client_weights(clients, out_dir)

    client_summary = []
    for client_id, group in clients.groupby("client_id"):
        client_summary.append(
            {
                "client_id": int(client_id),
                "is_malicious": int(group["is_malicious"].iloc[0]),
                "attack_type": group["attack_type"].iloc[0],
                "mean_update_norm": round(float(group["update_norm"].mean()), 6),
                "mean_aggregation_weight": round(float(group["aggregation_weight"].mean()), 6),
                "zero_weight_rounds": int((group["aggregation_weight"] <= 0).sum()),
                "rounds": int(len(group)),
            }
        )
    write_csv(
        out_dir / "client_audit_summary.csv",
        client_summary,
        [
            "client_id",
            "is_malicious",
            "attack_type",
            "mean_update_norm",
            "mean_aggregation_weight",
            "zero_weight_rounds",
            "rounds",
        ],
    )

    chain_rows = []
    for block in blocks[:5] + blocks[-5:]:
        metrics_payload = block["payload"]["metrics"]
        chain_rows.append(
            {
                "round": block["round"],
                "previous_hash": block["previous_hash"],
                "hash": block["hash"],
                "model_hash": block["payload"]["model_hash"],
                "clean_accuracy": metrics_payload["clean_accuracy"],
                "backdoor_asr": metrics_payload["backdoor_asr"],
                "zero_weight_rate": metrics_payload.get("zero_weight_rate", ""),
            }
        )
    write_csv(
        out_dir / "audit_chain_excerpt.csv",
        chain_rows,
        ["round", "previous_hash", "hash", "model_hash", "clean_accuracy", "backdoor_asr", "zero_weight_rate"],
    )

    malicious = [row for row in client_summary if row["is_malicious"] == 1]
    benign = [row for row in client_summary if row["is_malicious"] == 0]
    mean_mal_weight = sum(row["mean_aggregation_weight"] for row in malicious) / len(malicious)
    mean_benign_weight = sum(row["mean_aggregation_weight"] for row in benign) / len(benign)
    mean_mal_zero = sum(row["zero_weight_rounds"] for row in malicious) / len(malicious)
    mean_benign_zero = sum(row["zero_weight_rounds"] for row in benign) / len(benign)
    final_metrics = summary.get("final_metrics", {})
    final_row = metrics.iloc[-1]
    final_acc = float(summary.get("final_clean_accuracy", final_metrics.get("clean_accuracy", final_row["clean_accuracy"])))
    best_acc = float(summary.get("best_clean_accuracy", metrics["clean_accuracy"].max()))
    final_asr = float(summary.get("final_backdoor_asr", final_row["backdoor_asr"]))
    num_rounds = int(summary.get("num_rounds", final_row["round"]))

    report = f"""# Audit Case Study

## Run

- Run directory: `{run_dir}`
- Dataset: {config.get("dataset")}
- Data split: {"IID" if config.get("iid") else "Non-IID"} (alpha={config.get("alpha")})
- Attack: {config.get("attack_type")}
- Aggregation: {config.get("aggregation")}
- Seed: {config.get("seed")}
- Rounds: {num_rounds}
- Final clean accuracy: {final_acc:.2f}%
- Best clean accuracy: {best_acc:.2f}%
- Final ASR: {final_asr:.2f}%
- Chain linkage valid: {chain_ok}
- Stored audit blocks: {len(blocks)}

## Client-Level Audit Summary

- Malicious clients: {len(malicious)}
- Benign clients: {len(benign)}
- Mean aggregation weight, malicious clients: {mean_mal_weight:.4f}
- Mean aggregation weight, benign clients: {mean_benign_weight:.4f}
- Mean zero-weight rounds, malicious clients: {mean_mal_zero:.1f}
- Mean zero-weight rounds, benign clients: {mean_benign_zero:.1f}

## Interpretation

This case illustrates the audit function of the proposed method. The two sign-flip attackers receive near-zero mean aggregation weight across rounds, while benign clients retain nonzero contribution weights. The audit chain records per-round model hashes, metrics, client update metadata, aggregation weights, and block hashes, allowing later reconstruction of why a client update affected or did not affect the global model.

The case should be used as qualitative evidence of traceability and decision reconstruction. It should not be presented as standalone proof of malicious-client detection performance; aggregate accuracy and ASR claims should rely on the main tables.

## Generated Artifacts

- `audit_case_round_metrics.png/.pdf`
- `audit_case_client_weights.png/.pdf`
- `client_audit_summary.csv`
- `audit_chain_excerpt.csv`
"""
    (out_dir / "audit_case_report.md").write_text(report, encoding="utf-8")

    print(f"Wrote audit case to {out_dir}")
    print(f"Chain linkage valid: {chain_ok}; blocks: {len(blocks)}")


if __name__ == "__main__":
    main()
