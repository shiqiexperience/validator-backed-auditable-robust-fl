"""Generate reproducible config suites for the B-journal FL robustness study."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Dict, Iterable, List


BASE_CONFIG = {
    "data_dir": "./data",
    "output_dir": "experiments_b_journal",
    "device": "auto",
    "seed": 42,
    "num_clients": 10,
    "client_fraction": 1.0,
    "num_rounds": 5,
    "local_epochs": 1,
    "batch_size": 64,
    "num_workers": 0,
    "pin_memory": False,
    "persistent_workers": False,
    "prefetch_factor": 2,
    "amp": False,
    "allow_tf32": True,
    "cudnn_benchmark": True,
    "learning_rate": 0.01,
    "iid": True,
    "alpha": 0.5,
    "trim_ratio": 0.2,
    "threshold_scale": 2.5,
    "malicious_ratio": 0.2,
    "attack_strength": 5.0,
    "label_flip_mode": "cyclic",
    "backdoor_target_label": 0,
    "backdoor_asr_batches": 10,
    "early_stop_min_rounds": 5,
    "early_stop_max_loss": 1000000.0,
    "proposed_min_weight": 0.0,
    "proposed_weight_temperature": 1.2,
    "proposed_anomaly_reject_threshold": 4.0,
    "proposed_direction_reject_threshold": -0.4,
    "proposed_fallback_accept_fraction": 0.5,
}


def write_config(path: Path, payload: Dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, ensure_ascii=False)


def apply_profile(cfg: Dict, profile: str) -> Dict:
    if profile == "cuda":
        cache_small_dataset = cfg.get("dataset") in {"MNIST", "FashionMNIST"}
        cfg.update(
            {
                "device": "cuda",
                "batch_size": 256 if cache_small_dataset else 128,
                "num_workers": 0,
                "pin_memory": False if cache_small_dataset else True,
                "persistent_workers": False,
                "cache_dataset_tensors": cache_small_dataset,
                "cache_dataset_device": "cuda" if cache_small_dataset else "cpu",
                "amp": True,
                "allow_tf32": True,
                "cudnn_benchmark": True,
            }
        )
    return cfg


def make_config(dataset: str, aggregation: str, attack: str, iid: bool, rounds: int, seed: int, profile: str) -> Dict:
    cfg = dict(BASE_CONFIG)
    cfg.update(
        {
            "experiment_name": f"{dataset.lower()}_{'iid' if iid else 'noniid'}_{attack}_{aggregation}",
            "dataset": dataset,
            "aggregation": aggregation,
            "attack_type": attack,
            "iid": iid,
            "num_rounds": rounds,
            "seed": seed,
        }
    )
    if attack in {"label_flip", "label_flipping", "backdoor"}:
        cfg["attack_strength"] = 1.0
    return apply_profile(cfg, profile)


def generate_smoke(out_dir: Path, profile: str) -> List[Path]:
    paths = []
    for aggregation in ["fedavg", "krum", "trimmed_mean", "median", "norm_filter", "proposed"]:
        cfg = make_config("MNIST", aggregation, "sign_flip", True, rounds=3, seed=42, profile=profile)
        path = out_dir / f"{cfg['experiment_name']}.json"
        write_config(path, cfg)
        paths.append(path)
    return paths


def generate_core(out_dir: Path, profile: str) -> List[Path]:
    """Generate a compact paper-grade matrix.

    This suite is designed to avoid late-stage experiment inflation while still
    covering the evidence reviewers usually expect: main baselines, Non-IID,
    adaptive attack, targeted backdoor, ablation, malicious-ratio sensitivity,
    and repeated seeds.
    """
    paths = []
    seeds = [42, 43, 44]
    datasets = ["FashionMNIST", "CIFAR10"]
    main_aggregations = ["fedavg", "krum", "trimmed_mean", "median", "norm_filter", "proposed"]
    main_attacks = ["sign_flip", "adaptive_scaling", "backdoor"]
    distributions = [True, False]

    # Main comparison: 2 datasets x 2 distributions x 3 attacks x 6 methods x 3 seeds.
    for dataset in datasets:
        for iid in distributions:
            for attack in main_attacks:
                for aggregation in main_aggregations:
                    for seed in seeds:
                        cfg = make_config(dataset, aggregation, attack, iid, rounds=80, seed=seed, profile=profile)
                        cfg["experiment_name"] = (
                            f"core_{dataset.lower()}_{'iid' if iid else 'noniid'}_"
                            f"{attack}_{aggregation}_s{seed}"
                        )
                        if dataset == "CIFAR10":
                            cfg["num_rounds"] = 120
                            cfg["learning_rate"] = 0.005
                        path = out_dir / f"{cfg['experiment_name']}.json"
                        write_config(path, cfg)
                        paths.append(path)

    # Attack breadth: proposed method only, to show it is not tuned to one attack.
    extra_attacks = ["gaussian_noise", "model_poisoning", "label_flip"]
    for dataset in datasets:
        for iid in distributions:
            for attack in extra_attacks:
                for seed in seeds:
                    cfg = make_config(dataset, "proposed", attack, iid, rounds=80, seed=seed, profile=profile)
                    cfg["experiment_name"] = f"core_extra_{dataset.lower()}_{'iid' if iid else 'noniid'}_{attack}_proposed_s{seed}"
                    if dataset == "CIFAR10":
                        cfg["num_rounds"] = 120
                        cfg["learning_rate"] = 0.005
                    path = out_dir / f"{cfg['experiment_name']}.json"
                    write_config(path, cfg)
                    paths.append(path)

    # Malicious-ratio sensitivity: proposed vs strongest simple baseline only.
    for dataset in datasets:
        for ratio in [0.1, 0.2, 0.4]:
            for aggregation in ["trimmed_mean", "proposed"]:
                for seed in seeds:
                    cfg = make_config(dataset, aggregation, "adaptive_scaling", False, rounds=80, seed=seed, profile=profile)
                    cfg["malicious_ratio"] = ratio
                    cfg["experiment_name"] = f"core_ratio_{dataset.lower()}_noniid_adaptive_{aggregation}_r{ratio}_s{seed}"
                    if dataset == "CIFAR10":
                        cfg["num_rounds"] = 120
                        cfg["learning_rate"] = 0.005
                    path = out_dir / f"{cfg['experiment_name']}.json"
                    write_config(path, cfg)
                    paths.append(path)

    return paths


def generate_main(out_dir: Path, profile: str) -> List[Path]:
    paths = []
    datasets = ["FashionMNIST", "CIFAR10"]
    aggregations = ["fedavg", "krum", "trimmed_mean", "median", "norm_filter", "proposed"]
    attacks = ["sign_flip", "gaussian_noise", "model_poisoning", "adaptive_scaling", "label_flip", "backdoor"]
    distributions = [True, False]

    for dataset in datasets:
        for iid in distributions:
            for attack in attacks:
                for aggregation in aggregations:
                    cfg = make_config(dataset, aggregation, attack, iid, rounds=100, seed=42, profile=profile)
                    if dataset == "CIFAR10":
                        cfg["num_rounds"] = 150
                        cfg["learning_rate"] = 0.005
                    path = out_dir / f"{cfg['experiment_name']}.json"
                    write_config(path, cfg)
                    paths.append(path)
    return paths


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--suite", choices=["smoke", "core", "main"], default="smoke")
    parser.add_argument("--profile", choices=["cpu", "cuda"], default="cpu")
    parser.add_argument("--out-dir", default="configs/b_journal_suite")
    args = parser.parse_args()

    out_dir = Path(args.out_dir)
    if args.suite == "smoke":
        paths = generate_smoke(out_dir, args.profile)
    elif args.suite == "core":
        paths = generate_core(out_dir, args.profile)
    else:
        paths = generate_main(out_dir, args.profile)

    manifest = out_dir / f"{args.suite}_manifest.txt"
    with open(manifest, "w", encoding="utf-8") as handle:
        for path in paths:
            handle.write(str(path) + "\n")

    print(f"Generated {len(paths)} configs")
    print(f"Manifest: {manifest}")


if __name__ == "__main__":
    main()
