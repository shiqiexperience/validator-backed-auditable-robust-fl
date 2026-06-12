"""Generate publication-oriented figures from cleaned paper tables."""

from __future__ import annotations

import argparse
from pathlib import Path

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd


METHOD_ORDER = ["fedavg", "krum", "trimmed_mean", "median", "norm_filter", "proposed"]
METHOD_LABELS = {
    "fedavg": "FedAvg",
    "krum": "Krum",
    "trimmed_mean": "Trimmed Mean",
    "median": "Median",
    "norm_filter": "Norm Filter",
    "proposed": "Proposed",
}
ATTACK_ORDER = ["sign_flip", "adaptive_scaling", "backdoor"]
ATTACK_LABELS = {
    "sign_flip": "Sign Flip",
    "adaptive_scaling": "Adaptive Scaling",
    "backdoor": "Backdoor",
}
COLORS = {
    "fedavg": "#6b7280",
    "krum": "#8b5cf6",
    "trimmed_mean": "#2563eb",
    "median": "#0891b2",
    "norm_filter": "#16a34a",
    "proposed": "#dc2626",
}


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


def grouped_bars(
    df: pd.DataFrame,
    out_dir: Path,
    name: str,
    title: str,
    iid_value: str | None = None,
) -> None:
    if iid_value is not None:
        df = df[df["iid"].astype(str) == iid_value]

    fig, axes = plt.subplots(1, 3, figsize=(12, 3.2), sharey=True)
    x = np.arange(len(METHOD_ORDER))

    for ax, attack in zip(axes, ATTACK_ORDER):
        subset = df[df["attack_type"] == attack].set_index("aggregation")
        acc = [float(subset.loc[m, "acc_mean"]) if m in subset.index else np.nan for m in METHOD_ORDER]
        err = [float(subset.loc[m, "acc_std"]) if m in subset.index else 0.0 for m in METHOD_ORDER]
        bars = ax.bar(
            x,
            acc,
            yerr=err,
            capsize=2.5,
            color=[COLORS[m] for m in METHOD_ORDER],
            edgecolor="#111827",
            linewidth=0.3,
        )
        ax.set_title(ATTACK_LABELS[attack])
        ax.set_xticks(x)
        ax.set_xticklabels([METHOD_LABELS[m] for m in METHOD_ORDER], rotation=35, ha="right")
        ax.set_ylim(0, 100)
        ax.set_ylabel("Clean accuracy (%)")

        asr_ax = ax.twinx()
        asr = [float(subset.loc[m, "asr_mean"]) if m in subset.index else np.nan for m in METHOD_ORDER]
        asr_ax.plot(x, asr, color="#111827", marker="o", linewidth=1.3, markersize=3.2, label="ASR")
        asr_ax.set_ylim(0, max(10, np.nanmax(asr) * 1.18))
        asr_ax.set_ylabel("ASR (%)")
        asr_ax.grid(False)

        for bar, method in zip(bars, METHOD_ORDER):
            if method == "proposed":
                bar.set_hatch("//")

    handles = [plt.Rectangle((0, 0), 1, 1, color=COLORS[m]) for m in METHOD_ORDER]
    labels = [METHOD_LABELS[m] for m in METHOD_ORDER]
    fig.legend(handles, labels, loc="upper center", ncol=6, frameon=False, bbox_to_anchor=(0.5, 1.08))
    fig.suptitle(title, y=1.18, fontsize=12)
    save(fig, out_dir, name)


def proposed_vs_norm(df: pd.DataFrame, out_dir: Path) -> None:
    rows = df[df["aggregation"].isin(["norm_filter", "proposed"])].copy()
    rows["condition"] = rows["dataset"] + " " + rows["iid"].astype(str).map({"True": "IID", "False": "Non-IID"}) + "\n" + rows["attack_type"].map(ATTACK_LABELS)
    conditions = list(dict.fromkeys(rows["condition"]))
    x = np.arange(len(conditions))
    width = 0.35

    fig, ax = plt.subplots(figsize=(12, 3.6))
    for offset, method in [(-width / 2, "norm_filter"), (width / 2, "proposed")]:
        subset = rows[rows["aggregation"] == method].set_index("condition")
        values = [float(subset.loc[c, "acc_mean"]) if c in subset.index else np.nan for c in conditions]
        errors = [float(subset.loc[c, "acc_std"]) if c in subset.index else 0.0 for c in conditions]
        ax.bar(
            x + offset,
            values,
            width,
            yerr=errors,
            capsize=2.5,
            label=METHOD_LABELS[method],
            color=COLORS[method],
            edgecolor="#111827",
            linewidth=0.3,
            hatch="//" if method == "proposed" else None,
        )

    ax.set_xticks(x)
    ax.set_xticklabels(conditions, rotation=35, ha="right")
    ax.set_ylim(65, 91)
    ax.set_ylabel("Clean accuracy (%)")
    ax.set_title("Proposed vs. Norm Filter: Clean Accuracy")
    ax.legend(frameon=False, ncol=2)
    save(fig, out_dir, "proposed_vs_norm_filter_accuracy")

    fig, ax = plt.subplots(figsize=(12, 3.6))
    for offset, method in [(-width / 2, "norm_filter"), (width / 2, "proposed")]:
        subset = rows[rows["aggregation"] == method].set_index("condition")
        values = [float(subset.loc[c, "asr_mean"]) if c in subset.index else np.nan for c in conditions]
        errors = [float(subset.loc[c, "asr_std"]) if c in subset.index else 0.0 for c in conditions]
        ax.bar(
            x + offset,
            values,
            width,
            yerr=errors,
            capsize=2.5,
            label=METHOD_LABELS[method],
            color=COLORS[method],
            edgecolor="#111827",
            linewidth=0.3,
            hatch="//" if method == "proposed" else None,
        )

    ax.set_xticks(x)
    ax.set_xticklabels(conditions, rotation=35, ha="right")
    ax.set_ylabel("Attack success rate (%)")
    ax.set_title("Proposed vs. Norm Filter: ASR")
    ax.legend(frameon=False, ncol=2)
    save(fig, out_dir, "proposed_vs_norm_filter_asr")


def ratio_sensitivity(df: pd.DataFrame, out_dir: Path) -> None:
    ratios = sorted(df["malicious_ratio"].astype(float).unique())
    fig, axes = plt.subplots(1, 2, figsize=(9, 3.4))

    for method in ["norm_filter", "trimmed_mean", "proposed"]:
        subset = df[df["aggregation"] == method].sort_values("malicious_ratio")
        x = subset["malicious_ratio"].astype(float).to_numpy() * 100
        axes[0].errorbar(
            x,
            subset["acc_mean"].astype(float),
            yerr=subset["acc_std"].astype(float),
            marker="o",
            linewidth=1.6,
            capsize=3,
            color=COLORS[method],
            label=METHOD_LABELS[method],
        )
        axes[1].errorbar(
            x,
            subset["asr_mean"].astype(float),
            yerr=subset["asr_std"].astype(float),
            marker="o",
            linewidth=1.6,
            capsize=3,
            color=COLORS[method],
            label=METHOD_LABELS[method],
        )

    for ax in axes:
        ax.set_xticks([r * 100 for r in ratios])
        ax.set_xlabel("Malicious clients (%)")
    axes[0].set_ylabel("Clean accuracy (%)")
    axes[0].set_title("Accuracy under Increasing Malicious Ratio")
    axes[1].set_ylabel("ASR (%)")
    axes[1].set_title("ASR under Increasing Malicious Ratio")
    handles, labels = axes[0].get_legend_handles_labels()
    fig.legend(handles, labels, loc="lower center", ncol=3, frameon=False, bbox_to_anchor=(0.5, -0.02))
    fig.tight_layout(rect=(0, 0.08, 1, 1))
    save(fig, out_dir, "malicious_ratio_sensitivity")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--tables-dir", default="experiments_b_journal/paper_tables")
    parser.add_argument("--out-dir", default="experiments_b_journal/paper_figures")
    args = parser.parse_args()

    style()
    tables_dir = Path(args.tables_dir)
    out_dir = Path(args.out_dir)

    fashion = pd.read_csv(tables_dir / "fashionmnist_main_table.csv")
    cifar = pd.read_csv(tables_dir / "cifar10_noniid_main_table.csv")
    ratio = pd.read_csv(tables_dir / "ratio_sensitivity_table.csv")
    proposed_norm = pd.read_csv(tables_dir / "proposed_vs_norm_filter.csv")

    grouped_bars(fashion, out_dir, "fashionmnist_iid_main", "Fashion-MNIST IID Main Results", iid_value="True")
    grouped_bars(fashion, out_dir, "fashionmnist_noniid_main", "Fashion-MNIST Non-IID Main Results", iid_value="False")
    grouped_bars(cifar, out_dir, "cifar10_noniid_main", "CIFAR-10 Non-IID Main Results")
    proposed_vs_norm(proposed_norm, out_dir)
    ratio_sensitivity(ratio, out_dir)

    print(f"Wrote figures to {out_dir}")


if __name__ == "__main__":
    main()
