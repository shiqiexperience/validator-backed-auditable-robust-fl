"""Aggregation rules for robust federated learning benchmarks."""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

import torch


StateDict = Dict[str, torch.Tensor]


def clone_state(state: Mapping[str, torch.Tensor]) -> StateDict:
    return {name: tensor.detach().clone() for name, tensor in state.items()}


def _float_keys(state: Mapping[str, torch.Tensor]) -> List[str]:
    return [name for name, tensor in state.items() if torch.is_floating_point(tensor)]


def update_vector(global_state: Mapping[str, torch.Tensor], client_state: Mapping[str, torch.Tensor]) -> torch.Tensor:
    parts = []
    for name in _float_keys(global_state):
        parts.append((client_state[name].detach().float() - global_state[name].detach().float()).reshape(-1))
    if not parts:
        device = next(iter(global_state.values())).device
        return torch.empty(0, device=device)
    return torch.cat(parts)


def update_norm(global_state: Mapping[str, torch.Tensor], client_state: Mapping[str, torch.Tensor]) -> float:
    vec = update_vector(global_state, client_state)
    return float(torch.linalg.vector_norm(vec).item()) if vec.numel() else 0.0


def cosine_similarity(a: torch.Tensor, b: torch.Tensor) -> float:
    if a.numel() == 0 or b.numel() == 0:
        return 0.0
    denom = torch.linalg.vector_norm(a) * torch.linalg.vector_norm(b)
    if float(denom.item()) == 0.0:
        return 0.0
    return float(torch.dot(a, b).item() / denom.item())


def apply_update(global_state: Mapping[str, torch.Tensor], update: torch.Tensor) -> StateDict:
    out = clone_state(global_state)
    cursor = 0
    for name in _float_keys(global_state):
        tensor = global_state[name]
        numel = tensor.numel()
        delta = update[cursor : cursor + numel].reshape(tensor.shape).to(device=tensor.device, dtype=tensor.dtype)
        out[name] = tensor.detach().clone() + delta
        cursor += numel
    return out


def weighted_average(
    client_states: Sequence[Mapping[str, torch.Tensor]],
    sample_counts: Sequence[int],
    weights: Optional[Sequence[float]] = None,
) -> StateDict:
    if not client_states:
        raise ValueError("client_states must not be empty")

    if weights is None:
        raw_weights = [float(n) for n in sample_counts]
    else:
        raw_weights = [float(w) * float(n) for w, n in zip(weights, sample_counts)]

    total_weight = sum(raw_weights)
    if total_weight <= 0:
        raw_weights = [1.0 for _ in client_states]
        total_weight = float(len(client_states))

    out = clone_state(client_states[0])
    for name, tensor in out.items():
        if not torch.is_floating_point(tensor):
            out[name] = tensor.detach().clone()
            continue

        acc = torch.zeros_like(tensor, dtype=torch.float32)
        for state, weight in zip(client_states, raw_weights):
            acc += state[name].detach().float() * (weight / total_weight)
        out[name] = acc.to(dtype=tensor.dtype, device=tensor.device)
    return out


def krum(
    global_state: Mapping[str, torch.Tensor],
    client_states: Sequence[Mapping[str, torch.Tensor]],
    sample_counts: Sequence[int],
    num_malicious: int,
) -> Tuple[StateDict, List[float]]:
    if len(client_states) < 3:
        return weighted_average(client_states, sample_counts), [1.0 for _ in client_states]

    vectors = [update_vector(global_state, state) for state in client_states]
    n = len(vectors)
    nearest = max(1, n - num_malicious - 2)
    scores = []
    for i, vec_i in enumerate(vectors):
        distances = []
        for j, vec_j in enumerate(vectors):
            if i == j:
                continue
            distances.append(float(torch.sum((vec_i - vec_j) ** 2).item()))
        distances.sort()
        scores.append(sum(distances[:nearest]))

    winner = min(range(n), key=lambda idx: scores[idx])
    weights = [0.0 for _ in client_states]
    weights[winner] = 1.0
    return clone_state(client_states[winner]), weights


def trimmed_mean(
    global_state: Mapping[str, torch.Tensor],
    client_states: Sequence[Mapping[str, torch.Tensor]],
    trim_ratio: float,
) -> Tuple[StateDict, List[float]]:
    n = len(client_states)
    trim = min(int(math.floor(n * trim_ratio)), max(0, (n - 1) // 2))
    out = clone_state(client_states[0])
    for name, tensor in out.items():
        if not torch.is_floating_point(tensor):
            continue
        stacked = torch.stack([state[name].detach().float() for state in client_states], dim=0)
        sorted_vals, _ = torch.sort(stacked, dim=0)
        if trim > 0:
            sorted_vals = sorted_vals[trim:-trim]
        out[name] = sorted_vals.mean(dim=0).to(dtype=tensor.dtype, device=tensor.device)
    return out, [1.0 for _ in client_states]


def coordinate_median(client_states: Sequence[Mapping[str, torch.Tensor]]) -> Tuple[StateDict, List[float]]:
    out = clone_state(client_states[0])
    for name, tensor in out.items():
        if not torch.is_floating_point(tensor):
            continue
        stacked = torch.stack([state[name].detach().float() for state in client_states], dim=0)
        out[name] = stacked.median(dim=0).values.to(dtype=tensor.dtype, device=tensor.device)
    return out, [1.0 for _ in client_states]


def norm_filter(
    global_state: Mapping[str, torch.Tensor],
    client_states: Sequence[Mapping[str, torch.Tensor]],
    sample_counts: Sequence[int],
    threshold_scale: float,
) -> Tuple[StateDict, List[float], Dict[str, float]]:
    norms = [update_norm(global_state, state) for state in client_states]
    center = float(torch.tensor(norms).median().item()) if norms else 0.0
    deviations = [abs(n - center) for n in norms]
    mad = float(torch.tensor(deviations).median().item()) if deviations else 0.0
    threshold = center + threshold_scale * max(mad, 1e-12)
    weights = [1.0 if norm <= threshold else 0.0 for norm in norms]
    selected = [state for state, weight in zip(client_states, weights) if weight > 0]
    selected_counts = [count for count, weight in zip(sample_counts, weights) if weight > 0]
    if not selected:
        selected = list(client_states)
        selected_counts = list(sample_counts)
        weights = [1.0 for _ in client_states]
    return weighted_average(selected, selected_counts), weights, {"norm_center": center, "norm_threshold": threshold}


def fltrust(
    global_state: Mapping[str, torch.Tensor],
    client_states: Sequence[Mapping[str, torch.Tensor]],
    sample_counts: Sequence[int],
    client_ids: Sequence[int],
    root_state: Mapping[str, torch.Tensor],
) -> Tuple[StateDict, List[float], List[Dict[str, float]]]:
    """FLTrust-style trust bootstrapping with a trusted root update."""

    root_update = update_vector(global_state, root_state)
    root_norm = float(torch.linalg.vector_norm(root_update).item()) if root_update.numel() else 0.0
    if root_norm <= 0.0:
        weights = [1.0 for _ in client_states]
        decisions = [
            {
                "client_id": float(client_id),
                "trust_score": 1.0,
                "root_update_norm": root_norm,
                "client_update_norm": update_norm(global_state, state),
                "aggregation_weight": 1.0,
                "rejected": 0.0,
            }
            for client_id, state in zip(client_ids, client_states)
        ]
        return weighted_average(client_states, sample_counts), weights, decisions

    normalized_states: List[StateDict] = []
    weights: List[float] = []
    decisions: List[Dict[str, float]] = []
    for client_id, state in zip(client_ids, client_states):
        update = update_vector(global_state, state)
        client_norm = float(torch.linalg.vector_norm(update).item()) if update.numel() else 0.0
        trust = max(0.0, cosine_similarity(update, root_update))
        if client_norm > 0.0:
            normalized_update = update * (root_norm / client_norm)
            normalized_states.append(apply_update(global_state, normalized_update))
        else:
            normalized_states.append(clone_state(global_state))
        weights.append(trust)
        decisions.append(
            {
                "client_id": float(client_id),
                "trust_score": trust,
                "root_update_norm": root_norm,
                "client_update_norm": client_norm,
                "aggregation_weight": trust,
                "rejected": 1.0 if trust <= 1e-12 else 0.0,
            }
        )

    return weighted_average(normalized_states, sample_counts, weights), weights, decisions


def flame(
    global_state: Mapping[str, torch.Tensor],
    client_states: Sequence[Mapping[str, torch.Tensor]],
    sample_counts: Sequence[int],
    client_ids: Sequence[int],
    cluster_eps: float = 0.35,
    min_samples: int = 2,
    noise_multiplier: float = 0.001,
) -> Tuple[StateDict, List[float], List[Dict[str, float]]]:
    """FLAME-style backdoor defense with clustering, clipping, and noise."""

    if not client_states:
        raise ValueError("client_states must not be empty")

    updates = [update_vector(global_state, state) for state in client_states]
    norms = [float(torch.linalg.vector_norm(vec).item()) if vec.numel() else 0.0 for vec in updates]
    n = len(updates)

    labels = [0 for _ in range(n)]
    selected_indices = list(range(n))
    if n >= max(2, min_samples) and updates[0].numel():
        distance = torch.zeros((n, n), dtype=torch.float32)
        for i, vec_i in enumerate(updates):
            for j, vec_j in enumerate(updates):
                distance[i, j] = 1.0 - cosine_similarity(vec_i, vec_j)
        try:
            from sklearn.cluster import DBSCAN

            model = DBSCAN(eps=float(cluster_eps), min_samples=int(min_samples), metric="precomputed")
            labels = [int(label) for label in model.fit_predict(distance.detach().cpu().numpy()).tolist()]
            cluster_sizes: dict[int, int] = {}
            for label in labels:
                if label >= 0:
                    cluster_sizes[label] = cluster_sizes.get(label, 0) + 1
            if cluster_sizes:
                keep_label = max(cluster_sizes, key=lambda label: (cluster_sizes[label], -label))
                selected_indices = [idx for idx, label in enumerate(labels) if label == keep_label]
        except Exception:
            labels = [0 for _ in range(n)]
            selected_indices = list(range(n))

    selected_norms = [norms[idx] for idx in selected_indices if norms[idx] > 0.0]
    clip_norm = float(torch.tensor(selected_norms).median().item()) if selected_norms else 0.0

    clipped_updates = []
    clipped_counts = []
    weights = [0.0 for _ in client_states]
    decisions: List[Dict[str, float]] = []
    for idx, (client_id, update, norm) in enumerate(zip(client_ids, updates, norms)):
        selected = idx in selected_indices
        label = labels[idx] if idx < len(labels) else -1
        if selected:
            scale = 1.0
            if clip_norm > 0.0 and norm > clip_norm:
                scale = clip_norm / max(norm, 1e-12)
            clipped_updates.append(update * scale)
            clipped_counts.append(float(sample_counts[idx]))
            weights[idx] = 1.0
        decisions.append(
            {
                "client_id": float(client_id),
                "cluster_label": float(label),
                "selected_cluster": 1.0 if selected else 0.0,
                "client_update_norm": norm,
                "clip_norm": clip_norm,
                "aggregation_weight": weights[idx],
                "rejected": 0.0 if selected else 1.0,
            }
        )

    if not clipped_updates or sum(clipped_counts) <= 0.0:
        clipped_updates = updates
        clipped_counts = [float(count) for count in sample_counts]
        weights = [1.0 for _ in client_states]

    total = sum(clipped_counts)
    aggregate_update = torch.zeros_like(clipped_updates[0])
    for update, count in zip(clipped_updates, clipped_counts):
        aggregate_update += update * (count / total)

    # Calibrate per-coordinate noise so the total injected noise does not grow
    # with the square root of the model dimensionality.
    noise_std = max(0.0, float(noise_multiplier)) * max(clip_norm, 1e-12) / math.sqrt(
        max(int(aggregate_update.numel()), 1)
    )
    if noise_std > 0.0 and aggregate_update.numel():
        aggregate_update = aggregate_update + torch.randn_like(aggregate_update) * noise_std

    for decision in decisions:
        decision["noise_std"] = noise_std

    return apply_update(global_state, aggregate_update), weights, decisions


@dataclass
class ReputationState:
    reputations: Dict[int, float] = field(default_factory=dict)
    previous_updates: Dict[int, torch.Tensor] = field(default_factory=dict)

    def ensure_clients(self, client_ids: Iterable[int], initial: float = 1.0) -> None:
        for client_id in client_ids:
            self.reputations.setdefault(int(client_id), float(initial))


def proposed_reputation_aggregation(
    global_state: Mapping[str, torch.Tensor],
    client_states: Sequence[Mapping[str, torch.Tensor]],
    sample_counts: Sequence[int],
    client_ids: Sequence[int],
    rep_state: ReputationState,
    threshold_scale: float = 2.5,
    min_weight: float = 0.0,
    weight_temperature: float = 1.2,
    anomaly_reject_threshold: float = 4.0,
    direction_reject_threshold: float = -0.4,
    fallback_accept_fraction: float = 0.5,
    use_direction_score: bool = True,
    use_history_score: bool = True,
    use_hard_rejection: bool = True,
    norm_coefficient: float = 0.45,
    direction_coefficient: float = 0.35,
    history_coefficient: float = 0.20,
) -> Tuple[StateDict, List[float], List[Dict[str, float]]]:
    rep_state.ensure_clients(client_ids)
    updates = [update_vector(global_state, state) for state in client_states]
    norms = [float(torch.linalg.vector_norm(vec).item()) if vec.numel() else 0.0 for vec in updates]
    mean_update = torch.stack(updates).mean(dim=0) if updates and updates[0].numel() else torch.empty(0)

    center = float(torch.tensor(norms).median().item()) if norms else 0.0
    deviations = [abs(n - center) for n in norms]
    mad = float(torch.tensor(deviations).median().item()) if deviations else 0.0
    norm_scale = max(mad, 1e-12)

    decisions: List[Dict[str, float]] = []
    weights: List[float] = []

    for client_id, vec, norm in zip(client_ids, updates, norms):
        norm_score = max(0.0, (norm - center) / norm_scale)
        direction = cosine_similarity(vec, mean_update)
        direction_score = max(0.0, 1.0 - direction) if use_direction_score else 0.0

        prev_vec = rep_state.previous_updates.get(int(client_id))
        if prev_vec is None or not use_history_score:
            history_score = 0.0
        else:
            history_score = max(0.0, 1.0 - cosine_similarity(vec, prev_vec))

        components = {
            "norm": (float(norm_coefficient), norm_score),
            "direction": (float(direction_coefficient) if use_direction_score else 0.0, direction_score),
            "history": (float(history_coefficient) if use_history_score else 0.0, history_score),
        }
        total_component_weight = sum(weight for weight, _ in components.values())
        anomaly = sum(weight * value for weight, value in components.values()) / max(total_component_weight, 1e-12)
        old_rep = rep_state.reputations[int(client_id)]
        new_rep = max(0.05, min(1.5, 0.85 * old_rep + 0.15 * math.exp(-anomaly)))
        rep_state.reputations[int(client_id)] = new_rep
        rep_state.previous_updates[int(client_id)] = vec.detach().clone()

        hard_reject = False
        if use_hard_rejection:
            hard_reject = (
                anomaly > anomaly_reject_threshold
                or (norm_score > threshold_scale and direction < 0.0)
                or (use_direction_score and direction < direction_reject_threshold)
            )
        weight = 0.0 if hard_reject else max(min_weight, new_rep * math.exp(-weight_temperature * anomaly))
        weights.append(weight)

        decisions.append(
            {
                "client_id": float(client_id),
                "norm": norm,
                "direction": direction,
                "norm_score": norm_score,
                "history_score": history_score,
                "anomaly_score": anomaly,
                "reputation_before": old_rep,
                "reputation_after": new_rep,
                "aggregation_weight": weight,
                "rejected": 1.0 if hard_reject else 0.0,
                "use_direction_score": 1.0 if use_direction_score else 0.0,
                "use_history_score": 1.0 if use_history_score else 0.0,
                "use_hard_rejection": 1.0 if use_hard_rejection else 0.0,
                "norm_coefficient": float(norm_coefficient),
                "direction_coefficient": float(direction_coefficient),
                "history_coefficient": float(history_coefficient),
            }
        )

    if sum(weights) <= 0.0 and decisions:
        accept_count = max(1, int(math.ceil(len(decisions) * fallback_accept_fraction)))
        ranked = sorted(range(len(decisions)), key=lambda i: decisions[i]["anomaly_score"])
        accepted = set(ranked[:accept_count])
        weights = []
        for i, decision in enumerate(decisions):
            if i in accepted:
                fallback_weight = max(1e-6, decision["reputation_after"] * math.exp(-weight_temperature * decision["anomaly_score"]))
                weights.append(fallback_weight)
                decision["rejected"] = 0.0
                decision["aggregation_weight"] = fallback_weight
                decision["fallback_selected"] = 1.0
            else:
                weights.append(0.0)
                decision["fallback_selected"] = 0.0

    return weighted_average(client_states, sample_counts, weights), weights, decisions


def aggregate(
    method: str,
    global_state: Mapping[str, torch.Tensor],
    client_states: Sequence[Mapping[str, torch.Tensor]],
    sample_counts: Sequence[int],
    client_ids: Sequence[int],
    rep_state: Optional[ReputationState] = None,
    num_malicious: int = 0,
    trim_ratio: float = 0.2,
    threshold_scale: float = 2.5,
    proposed_min_weight: float = 0.0,
    proposed_weight_temperature: float = 1.2,
    proposed_anomaly_reject_threshold: float = 4.0,
    proposed_direction_reject_threshold: float = -0.4,
    proposed_fallback_accept_fraction: float = 0.5,
    proposed_use_direction_score: bool = True,
    proposed_use_history_score: bool = True,
    proposed_use_hard_rejection: bool = True,
    proposed_norm_coefficient: float = 0.45,
    proposed_direction_coefficient: float = 0.35,
    proposed_history_coefficient: float = 0.20,
    fltrust_root_state: Optional[Mapping[str, torch.Tensor]] = None,
    flame_cluster_eps: float = 0.35,
    flame_min_samples: int = 2,
    flame_noise_multiplier: float = 0.001,
) -> Tuple[StateDict, List[float], List[Dict[str, float]]]:
    method = method.lower()
    if method == "fedavg":
        return weighted_average(client_states, sample_counts), [1.0 for _ in client_states], []
    if method == "krum":
        state, weights = krum(global_state, client_states, sample_counts, num_malicious)
        return state, weights, []
    if method == "trimmed_mean":
        state, weights = trimmed_mean(global_state, client_states, trim_ratio)
        return state, weights, []
    if method == "median":
        state, weights = coordinate_median(client_states)
        return state, weights, []
    if method == "norm_filter":
        state, weights, extra = norm_filter(global_state, client_states, sample_counts, threshold_scale)
        decisions = [{"client_id": float(cid), "aggregation_weight": float(w), **extra} for cid, w in zip(client_ids, weights)]
        return state, weights, decisions
    if method == "fltrust":
        if fltrust_root_state is None:
            raise ValueError("fltrust_root_state is required for FLTrust aggregation")
        return fltrust(
            global_state=global_state,
            client_states=client_states,
            sample_counts=sample_counts,
            client_ids=client_ids,
            root_state=fltrust_root_state,
        )
    if method == "flame":
        return flame(
            global_state=global_state,
            client_states=client_states,
            sample_counts=sample_counts,
            client_ids=client_ids,
            cluster_eps=flame_cluster_eps,
            min_samples=flame_min_samples,
            noise_multiplier=flame_noise_multiplier,
        )
    if method == "proposed":
        if rep_state is None:
            raise ValueError("rep_state is required for proposed aggregation")
        return proposed_reputation_aggregation(
            global_state=global_state,
            client_states=client_states,
            sample_counts=sample_counts,
            client_ids=client_ids,
            rep_state=rep_state,
            threshold_scale=threshold_scale,
            min_weight=proposed_min_weight,
            weight_temperature=proposed_weight_temperature,
            anomaly_reject_threshold=proposed_anomaly_reject_threshold,
            direction_reject_threshold=proposed_direction_reject_threshold,
            fallback_accept_fraction=proposed_fallback_accept_fraction,
            use_direction_score=proposed_use_direction_score,
            use_history_score=proposed_use_history_score,
            use_hard_rejection=proposed_use_hard_rejection,
            norm_coefficient=proposed_norm_coefficient,
            direction_coefficient=proposed_direction_coefficient,
            history_coefficient=proposed_history_coefficient,
        )
    raise ValueError(f"Unknown aggregation method: {method}")
