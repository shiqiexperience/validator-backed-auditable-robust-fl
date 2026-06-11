"""Metrics and persistence helpers for robust FL experiments."""

from __future__ import annotations

import csv
import json
import os
from pathlib import Path
from typing import Dict, Iterable, Mapping, Sequence

import torch
import torch.nn as nn

from .attacks import add_backdoor_trigger


def ensure_dir(path: str | Path) -> Path:
    out = Path(path)
    out.mkdir(parents=True, exist_ok=True)
    return out


def write_json(path: str | Path, payload: Mapping) -> None:
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, ensure_ascii=False)


def append_csv(path: str | Path, row: Mapping, fieldnames: Sequence[str]) -> None:
    path = Path(path)
    exists = path.exists()
    with open(path, "a", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        if not exists:
            writer.writeheader()
        writer.writerow({name: row.get(name, "") for name in fieldnames})


def evaluate(model: nn.Module, loader, device: str) -> Dict[str, float]:
    model.eval()
    criterion = nn.CrossEntropyLoss()
    total_loss = 0.0
    correct = 0
    total = 0
    with torch.no_grad():
        for data, target in loader:
            data = data.to(device)
            target = target.to(device)
            output = model(data)
            total_loss += criterion(output, target).item() * data.size(0)
            correct += output.argmax(dim=1).eq(target).sum().item()
            total += target.numel()
    return {
        "test_loss": total_loss / max(total, 1),
        "clean_accuracy": 100.0 * correct / max(total, 1),
    }


def evaluate_backdoor_asr(model: nn.Module, loader, device: str, target_label: int = 0, max_batches: int = 20) -> float:
    model.eval()
    target_hits = 0
    total = 0
    with torch.no_grad():
        for batch_idx, (data, target) in enumerate(loader):
            if batch_idx >= max_batches:
                break
            data = add_backdoor_trigger(data).to(device)
            output = model(data)
            pred = output.argmax(dim=1).cpu()
            target = target.cpu()
            mask = target != target_label
            target_hits += pred[mask].eq(target_label).sum().item()
            total += int(mask.sum().item())
    return 100.0 * target_hits / max(total, 1)


def detection_summary(client_is_malicious: Sequence[bool], weights: Sequence[float], reject_threshold: float = 1e-8) -> Dict[str, float]:
    tp = fp = tn = fn = 0
    for is_bad, weight in zip(client_is_malicious, weights):
        rejected = weight <= reject_threshold
        if is_bad and rejected:
            tp += 1
        elif is_bad and not rejected:
            fn += 1
        elif not is_bad and rejected:
            fp += 1
        else:
            tn += 1

    precision = tp / max(tp + fp, 1)
    recall = tp / max(tp + fn, 1)
    f1 = 2 * precision * recall / max(precision + recall, 1e-12)
    return {
        "tp": float(tp),
        "fp": float(fp),
        "tn": float(tn),
        "fn": float(fn),
        "tpr": recall,
        "fpr": fp / max(fp + tn, 1),
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "false_rejection_rate": fp / max(fp + tn, 1),
    }
