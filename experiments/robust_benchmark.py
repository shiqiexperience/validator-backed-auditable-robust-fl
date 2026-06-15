"""Reproducible robust-FL benchmark runner for the B-journal study.

Example:
    python experiments/robust_benchmark.py --config configs/b_journal_smoke_mnist.json
"""

from __future__ import annotations

import argparse
import copy
import json
import os
import random
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Tuple

import numpy as np
import torch
import torch.nn as nn
import torch.optim as optim
from torch.utils.data import DataLoader, Subset, TensorDataset

try:
    sys.stdout.reconfigure(encoding="utf-8")
    sys.stderr.reconfigure(encoding="utf-8")
except AttributeError:
    pass

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.models.model_factory import create_model
from src.research.aggregation import ReputationState, aggregate, clone_state, update_norm
from src.research.attacks import add_backdoor_trigger, apply_update_attack, collusive_direction_attack, flip_labels
from src.research.audit import AuditChainLogger, verify_chain
from src.research.metrics import append_csv, detection_summary, ensure_dir, evaluate, evaluate_backdoor_asr, write_json
from src.utils.data_loader import FederatedDataLoader


ROUND_FIELDS = [
    "round",
    "aggregation",
    "clean_accuracy",
    "test_loss",
    "backdoor_asr",
    "rejection_rate",
    "zero_weight_rate",
    "hard_rejection_rate",
    "mean_aggregation_weight",
    "early_stopped",
    "stop_reason",
    "tpr",
    "fpr",
    "precision",
    "recall",
    "f1",
    "false_rejection_rate",
    "defense_time",
    "round_time",
]

CLIENT_FIELDS = [
    "round",
    "client_id",
    "is_malicious",
    "attack_type",
    "train_loss",
    "train_accuracy",
    "num_samples",
    "update_norm",
    "aggregation_weight",
    "selected",
]


def load_config(path: Path) -> Dict:
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def set_seed(seed: int) -> None:
    random.seed(seed)
    np.random.seed(seed)
    torch.manual_seed(seed)
    if torch.cuda.is_available():
        torch.cuda.manual_seed_all(seed)


def resolve_device(device: str) -> str:
    if device == "auto":
        return "cuda" if torch.cuda.is_available() else "cpu"
    return device


def configure_torch(config: Dict, device: str) -> None:
    if device == "cuda":
        torch.backends.cudnn.benchmark = bool(config.get("cudnn_benchmark", True))
        torch.backends.cuda.matmul.allow_tf32 = bool(config.get("allow_tf32", True))
        torch.backends.cudnn.allow_tf32 = bool(config.get("allow_tf32", True))


def make_loader(dataset, batch_size: int, shuffle: bool, device: str, config: Dict):
    num_workers = int(config.get("num_workers", 0))
    pin_memory = bool(config.get("pin_memory", device == "cuda"))
    kwargs = {
        "batch_size": batch_size,
        "shuffle": shuffle,
        "num_workers": num_workers,
        "pin_memory": pin_memory,
    }
    if num_workers > 0:
        kwargs["persistent_workers"] = bool(config.get("persistent_workers", True))
        kwargs["prefetch_factor"] = int(config.get("prefetch_factor", 2))
    return DataLoader(dataset, **kwargs)


def cache_dataset_tensors(dataset, device: str) -> TensorDataset:
    images = []
    labels = []
    for idx in range(len(dataset)):
        image, label = dataset[idx]
        images.append(image)
        labels.append(int(label))
    x = torch.stack(images, dim=0).to(device)
    y = torch.tensor(labels, dtype=torch.long, device=device)
    return TensorDataset(x, y)


def model_hash(model: nn.Module) -> str:
    import hashlib

    digest = hashlib.sha256()
    for name, tensor in sorted(model.state_dict().items()):
        digest.update(name.encode("utf-8"))
        digest.update(tensor.detach().cpu().numpy().tobytes())
    return digest.hexdigest()


def train_one_client(
    model: nn.Module,
    loader,
    device: str,
    epochs: int,
    lr: float,
    is_malicious: bool,
    attack_type: str,
    label_flip_mode: str,
    backdoor_target_label: int,
    use_amp: bool,
) -> Dict[str, float]:
    model.train()
    criterion = nn.CrossEntropyLoss()
    optimizer = optim.SGD(model.parameters(), lr=lr, momentum=0.9)
    total_loss = 0.0
    correct = 0
    total = 0
    batches = 0
    scaler = torch.amp.GradScaler("cuda", enabled=use_amp)

    for _ in range(epochs):
        for data, target in loader:
            data = data.to(device, non_blocking=True)
            target = target.to(device, non_blocking=True)
            train_target = target

            if is_malicious and attack_type in {"label_flip", "label_flipping"}:
                train_target = flip_labels(target, mode=label_flip_mode)
            elif is_malicious and attack_type == "backdoor":
                data = add_backdoor_trigger(data)
                train_target = torch.full_like(target, int(backdoor_target_label))

            optimizer.zero_grad()
            with torch.amp.autocast("cuda", enabled=use_amp):
                output = model(data)
                loss = criterion(output, train_target)
            scaler.scale(loss).backward()
            scaler.step(optimizer)
            scaler.update()

            total_loss += loss.item()
            correct += output.argmax(dim=1).eq(target).sum().item()
            total += target.numel()
            batches += 1

    return {
        "loss": total_loss / max(batches, 1),
        "accuracy": 100.0 * correct / max(total, 1),
        "num_samples": len(loader.dataset),
    }


def train_root_update(
    global_state: Dict[str, torch.Tensor],
    dataset_name: str,
    root_loader,
    device: str,
    epochs: int,
    lr: float,
    use_amp: bool,
) -> Dict[str, torch.Tensor]:
    root_model = create_model(dataset_name).to(device)
    root_model.load_state_dict(global_state)
    train_one_client(
        model=root_model,
        loader=root_loader,
        device=device,
        epochs=epochs,
        lr=lr,
        is_malicious=False,
        attack_type="none",
        label_flip_mode="cyclic",
        backdoor_target_label=0,
        use_amp=use_amp,
    )
    return clone_state(root_model.state_dict())


def choose_clients(num_clients: int, fraction: float) -> List[int]:
    selected_count = max(1, int(round(num_clients * fraction)))
    return sorted(np.random.choice(num_clients, selected_count, replace=False).tolist())


def malicious_clients(num_clients: int, malicious_ratio: float) -> List[int]:
    count = int(round(num_clients * malicious_ratio))
    return list(range(count))


def estimate_adaptive_threshold(global_state, client_states: List[Dict[str, torch.Tensor]], scale: float) -> float:
    norms = [update_norm(global_state, state) for state in client_states]
    if not norms:
        return 0.0
    center = float(torch.tensor(norms).median().item())
    deviations = [abs(n - center) for n in norms]
    mad = float(torch.tensor(deviations).median().item())
    return center + scale * max(mad, 1e-12)


def run(config: Dict, config_path: Path) -> Path:
    seed = int(config.get("seed", 42))
    set_seed(seed)
    device = resolve_device(str(config.get("device", "auto")))
    configure_torch(config, device)
    use_amp = bool(config.get("amp", device == "cuda")) and device == "cuda"

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    exp_name = config.get("experiment_name", "robust_benchmark")
    out_dir = ensure_dir(Path(config.get("output_dir", "experiments_b_journal")) / f"{exp_name}_{timestamp}")

    runtime_config = dict(config)
    runtime_config["resolved_device"] = device
    runtime_config["amp_enabled"] = use_amp
    runtime_config["config_path"] = str(config_path)
    runtime_config["started_at"] = timestamp
    write_json(out_dir / "config.json", runtime_config)

    data = FederatedDataLoader(
        dataset_name=config["dataset"],
        data_dir=config.get("data_dir", "./data"),
        num_clients=int(config["num_clients"]),
        batch_size=int(config["batch_size"]),
        iid=bool(config.get("iid", True)),
        alpha=float(config.get("alpha", 0.5)),
    )
    cache_tensors = bool(config.get("cache_dataset_tensors", False))
    cache_device = str(config.get("cache_dataset_device", "cpu"))
    if cache_tensors:
        if cache_device == "cuda" and device != "cuda":
            cache_device = "cpu"
        print(f"Caching dataset tensors on {cache_device}...")
        data.train_dataset = cache_dataset_tensors(data.train_dataset, cache_device)
        data.test_dataset = cache_dataset_tensors(data.test_dataset, cache_device)

    batch_size = int(config["batch_size"])
    test_loader = make_loader(data.test_dataset, batch_size=batch_size, shuffle=False, device=device, config=config)
    client_loaders = [
        make_loader(
            Subset(data.train_dataset, data.client_indices[client_id]),
            batch_size=batch_size,
            shuffle=True,
            device=device,
            config=config,
        )
        for client_id in range(int(config["num_clients"]))
    ]
    root_loader = None
    if str(config.get("aggregation", "fedavg")).lower() == "fltrust":
        root_samples = min(int(config.get("fltrust_root_samples", 100)), len(data.train_dataset))
        rng = np.random.default_rng(seed + 1009)
        root_indices = sorted(rng.choice(len(data.train_dataset), size=root_samples, replace=False).tolist())
        root_loader = make_loader(
            Subset(data.train_dataset, root_indices),
            batch_size=batch_size,
            shuffle=True,
            device=device,
            config=config,
        )

    global_model = create_model(config["dataset"]).to(device)
    rep_state = ReputationState()
    audit = AuditChainLogger(out_dir / "audit_chain.jsonl")

    bad_clients = set(malicious_clients(int(config["num_clients"]), float(config.get("malicious_ratio", 0.0))))
    aggregation_method = str(config.get("aggregation", "fedavg"))
    attack_type = str(config.get("attack_type", "none"))

    metrics_path = out_dir / "metrics_round.csv"
    client_path = out_dir / "client_round_metrics.csv"

    start_time = time.perf_counter()
    final_eval = {}
    early_stopped = False
    stop_reason = ""

    for round_idx in range(1, int(config["num_rounds"]) + 1):
        round_start = time.perf_counter()
        global_state = clone_state(global_model.state_dict())
        selected = choose_clients(int(config["num_clients"]), float(config.get("client_fraction", 1.0)))

        client_states = []
        sample_counts = []
        client_metrics = []

        for client_id in selected:
            local_model = create_model(config["dataset"]).to(device)
            local_model.load_state_dict(global_state)
            is_bad = client_id in bad_clients

            metrics = train_one_client(
                model=local_model,
                loader=client_loaders[client_id],
                device=device,
                epochs=int(config["local_epochs"]),
                lr=float(config["learning_rate"]),
                is_malicious=is_bad,
                attack_type=attack_type,
                label_flip_mode=str(config.get("label_flip_mode", "cyclic")),
                backdoor_target_label=int(config.get("backdoor_target_label", 0)),
                use_amp=use_amp,
            )

            client_state = clone_state(local_model.state_dict())
            sample_counts.append(int(metrics["num_samples"]))
            client_states.append(client_state)
            client_metrics.append({"client_id": client_id, "is_malicious": is_bad, **metrics})

        threshold = estimate_adaptive_threshold(global_state, client_states, float(config.get("threshold_scale", 2.5)))
        benign_states = [state for state, metrics in zip(client_states, client_metrics) if not bool(metrics["is_malicious"])]
        attacked_states = []
        for state, metrics in zip(client_states, client_metrics):
            is_bad = bool(metrics["is_malicious"])
            if is_bad and attack_type.lower() in {"collusive_direction", "dfl_collusion", "collusive_poisoning"}:
                attacked_states.append(
                    collusive_direction_attack(
                        global_state=global_state,
                        benign_states=benign_states,
                        strength=float(config.get("attack_strength", 1.0)),
                        adaptive_threshold=threshold,
                    )
                )
            else:
                attacked_states.append(
                    apply_update_attack(
                        attack=attack_type if is_bad else "none",
                        global_state=global_state,
                        client_state=state,
                        strength=float(config.get("attack_strength", 1.0)),
                        adaptive_threshold=threshold,
                    )
                )
        fltrust_root_state = None
        if aggregation_method.lower() == "fltrust":
            if root_loader is None:
                raise ValueError("root_loader is required for FLTrust")
            fltrust_root_state = train_root_update(
                global_state=global_state,
                dataset_name=str(config["dataset"]),
                root_loader=root_loader,
                device=device,
                epochs=int(config.get("fltrust_root_epochs", config["local_epochs"])),
                lr=float(config.get("fltrust_root_learning_rate", config["learning_rate"])),
                use_amp=use_amp,
            )

        defense_start = time.perf_counter()
        aggregated_state, weights, decisions = aggregate(
            method=aggregation_method,
            global_state=global_state,
            client_states=attacked_states,
            sample_counts=sample_counts,
            client_ids=selected,
            rep_state=rep_state,
            num_malicious=len([cid for cid in selected if cid in bad_clients]),
            trim_ratio=float(config.get("trim_ratio", 0.2)),
            threshold_scale=float(config.get("threshold_scale", 2.5)),
            proposed_min_weight=float(config.get("proposed_min_weight", 0.0)),
            proposed_weight_temperature=float(config.get("proposed_weight_temperature", 1.2)),
            proposed_anomaly_reject_threshold=float(config.get("proposed_anomaly_reject_threshold", 4.0)),
            proposed_direction_reject_threshold=float(config.get("proposed_direction_reject_threshold", -0.4)),
            proposed_fallback_accept_fraction=float(config.get("proposed_fallback_accept_fraction", 0.5)),
            proposed_use_direction_score=bool(config.get("proposed_use_direction_score", True)),
            proposed_use_history_score=bool(config.get("proposed_use_history_score", True)),
            proposed_use_hard_rejection=bool(config.get("proposed_use_hard_rejection", True)),
            proposed_norm_coefficient=float(config.get("proposed_norm_coefficient", 0.45)),
            proposed_direction_coefficient=float(config.get("proposed_direction_coefficient", 0.35)),
            proposed_history_coefficient=float(config.get("proposed_history_coefficient", 0.20)),
            fltrust_root_state=fltrust_root_state,
            flame_cluster_eps=float(config.get("flame_cluster_eps", 0.35)),
            flame_min_samples=int(config.get("flame_min_samples", 2)),
            flame_noise_multiplier=float(config.get("flame_noise_multiplier", 0.001)),
        )
        defense_time = time.perf_counter() - defense_start

        global_model.load_state_dict(aggregated_state)
        final_eval = evaluate(global_model, test_loader, device)
        backdoor_asr = evaluate_backdoor_asr(
            global_model,
            test_loader,
            device,
            target_label=int(config.get("backdoor_target_label", 0)),
            max_batches=int(config.get("backdoor_asr_batches", 20)),
        )

        detect = detection_summary([bool(m["is_malicious"]) for m in client_metrics], weights)
        zero_weight_rate = 100.0 * sum(1 for w in weights if w <= 1e-8) / max(len(weights), 1)
        hard_rejection_rate = 100.0 * sum(1 for d in decisions if float(d.get("rejected", 0.0)) > 0.0) / max(len(weights), 1)
        rejection_rate = zero_weight_rate
        mean_weight = float(np.mean(weights)) if weights else 0.0
        round_time = time.perf_counter() - round_start
        loss_value = float(final_eval["test_loss"])
        acc_value = float(final_eval["clean_accuracy"])
        max_loss = float(config.get("early_stop_max_loss", 1e6))
        min_rounds = int(config.get("early_stop_min_rounds", 5))
        random_acc = 100.0 / 10.0
        if round_idx >= min_rounds and (not np.isfinite(loss_value) or loss_value > max_loss):
            early_stopped = True
            stop_reason = f"diverged_loss>{max_loss}"
        elif round_idx >= min_rounds and acc_value <= random_acc + 0.5 and loss_value > 100.0:
            early_stopped = True
            stop_reason = "random_accuracy_with_exploding_loss"

        row = {
            "round": round_idx,
            "aggregation": aggregation_method,
            **final_eval,
            "backdoor_asr": backdoor_asr,
            "rejection_rate": rejection_rate,
            "zero_weight_rate": zero_weight_rate,
            "hard_rejection_rate": hard_rejection_rate,
            "mean_aggregation_weight": mean_weight,
            "early_stopped": int(early_stopped),
            "stop_reason": stop_reason,
            **detect,
            "defense_time": defense_time,
            "round_time": round_time,
        }
        append_csv(metrics_path, row, ROUND_FIELDS)

        client_rows = []
        for metrics, state, weight in zip(client_metrics, attacked_states, weights):
            client_row = {
                "round": round_idx,
                "client_id": metrics["client_id"],
                "is_malicious": int(metrics["is_malicious"]),
                "attack_type": attack_type if metrics["is_malicious"] else "none",
                "train_loss": metrics["loss"],
                "train_accuracy": metrics["accuracy"],
                "num_samples": metrics["num_samples"],
                "update_norm": update_norm(global_state, state),
                "aggregation_weight": weight,
                "selected": 1,
            }
            client_rows.append(client_row)
            append_csv(client_path, client_row, CLIENT_FIELDS)

        audit.append(
            round_idx,
            {
                "model_hash": model_hash(global_model),
                "metrics": row,
                "clients": client_rows,
                "decisions": decisions,
            },
        )

        print(
            f"Round {round_idx}: acc={final_eval['clean_accuracy']:.2f}% "
            f"loss={final_eval['test_loss']:.4f} asr={backdoor_asr:.2f}% "
            f"reject={rejection_rate:.1f}%"
        )
        if early_stopped:
            print(f"Early stopped at round {round_idx}: {stop_reason}")
            break

    summary = {
        "experiment_name": exp_name,
        "output_dir": str(out_dir),
        "aggregation": aggregation_method,
        "attack_type": attack_type,
        "malicious_clients": sorted(bad_clients),
        "final_metrics": final_eval,
        "early_stopped": early_stopped,
        "stop_reason": stop_reason,
        "chain_valid": verify_chain(out_dir / "audit_chain.jsonl"),
        "total_time": time.perf_counter() - start_time,
    }
    write_json(out_dir / "summary.json", summary)
    print(f"Saved results to {out_dir}")
    return out_dir


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", required=True, help="Path to a JSON experiment config.")
    args = parser.parse_args()

    config_path = Path(args.config)
    config = load_config(config_path)
    run(config, config_path)


if __name__ == "__main__":
    main()
