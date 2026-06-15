"""Model-update attacks for robust FL experiments."""

from __future__ import annotations

from typing import Mapping

import torch

from .aggregation import StateDict, apply_update, clone_state, update_norm, update_vector


def apply_update_attack(
    attack: str,
    global_state: Mapping[str, torch.Tensor],
    client_state: Mapping[str, torch.Tensor],
    strength: float = 1.0,
    adaptive_threshold: float | None = None,
) -> StateDict:
    attack = attack.lower()
    out = clone_state(client_state)

    if attack in {"none", "label_flip", "label_flipping", "backdoor"}:
        return out

    for name, tensor in client_state.items():
        if not torch.is_floating_point(tensor):
            continue
        delta = tensor.detach().float() - global_state[name].detach().float()
        if attack == "sign_flip":
            out[name] = (global_state[name].detach().float() - strength * delta).to(dtype=tensor.dtype, device=tensor.device)
        elif attack == "gaussian_noise":
            noise_scale = max(float(delta.std().item()), 1e-6) * strength
            out[name] = (tensor.detach().float() + torch.randn_like(delta) * noise_scale).to(dtype=tensor.dtype, device=tensor.device)
        elif attack in {"model_poison", "model_poisoning"}:
            out[name] = (global_state[name].detach().float() + delta * strength).to(dtype=tensor.dtype, device=tensor.device)
        elif attack == "adaptive_scaling":
            out[name] = tensor.detach().clone()
        else:
            raise ValueError(f"Unknown attack: {attack}")

    if attack == "adaptive_scaling" and adaptive_threshold is not None:
        current_norm = update_norm(global_state, out)
        if current_norm > adaptive_threshold and current_norm > 0:
            scale = 0.98 * adaptive_threshold / current_norm
            for name, tensor in out.items():
                if not torch.is_floating_point(tensor):
                    continue
                delta = tensor.detach().float() - global_state[name].detach().float()
                out[name] = (global_state[name].detach().float() + delta * scale).to(dtype=tensor.dtype, device=tensor.device)

    return out


def collusive_direction_attack(
    global_state: Mapping[str, torch.Tensor],
    benign_states: list[Mapping[str, torch.Tensor]],
    strength: float = 1.0,
    adaptive_threshold: float | None = None,
) -> StateDict:
    """Craft a shared malicious update against the benign mean direction."""

    if not benign_states:
        return clone_state(global_state)
    benign_updates = [update_vector(global_state, state) for state in benign_states]
    if not benign_updates or benign_updates[0].numel() == 0:
        return clone_state(global_state)
    target_update = -float(strength) * torch.stack(benign_updates).mean(dim=0)
    target_norm = float(torch.linalg.vector_norm(target_update).item())
    if adaptive_threshold is not None and target_norm > adaptive_threshold and target_norm > 0.0:
        target_update = target_update * (0.98 * float(adaptive_threshold) / target_norm)
    return apply_update(global_state, target_update)


def flip_labels(labels: torch.Tensor, num_classes: int = 10, mode: str = "cyclic") -> torch.Tensor:
    if mode == "cyclic":
        return (labels + 1) % num_classes
    if mode == "targeted":
        flipped = labels.clone()
        flipped[labels == 7] = 1
        flipped[labels == 3] = 8
        return flipped
    raise ValueError(f"Unknown label flip mode: {mode}")


def add_backdoor_trigger(data: torch.Tensor, value: float = 1.0) -> torch.Tensor:
    poisoned = data.clone()
    poisoned[..., -4:, -4:] = value
    return poisoned
