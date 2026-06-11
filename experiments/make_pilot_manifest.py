"""Create small balanced manifests from a generated core suite."""

from __future__ import annotations

import argparse
import json
from pathlib import Path


def read_manifest(path: Path):
    with open(path, "r", encoding="utf-8") as handle:
        return [Path(line.strip()) for line in handle if line.strip()]


def load_config(path: Path):
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--out", required=True)
    parser.add_argument("--dataset", default="FashionMNIST")
    parser.add_argument("--attack", default="sign_flip")
    parser.add_argument("--iid", choices=["true", "false"], default="true")
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()

    want_iid = args.iid == "true"
    selected = []
    for path in read_manifest(Path(args.manifest)):
        cfg = load_config(path)
        if (
            cfg.get("dataset") == args.dataset
            and cfg.get("attack_type") == args.attack
            and bool(cfg.get("iid")) == want_iid
            and int(cfg.get("seed")) == args.seed
        ):
            selected.append(path)

    order = {"fedavg": 0, "krum": 1, "trimmed_mean": 2, "median": 3, "norm_filter": 4, "proposed": 5}
    selected.sort(key=lambda p: order.get(load_config(p).get("aggregation"), 99))

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    with open(out, "w", encoding="utf-8") as handle:
        for path in selected:
            handle.write(str(path) + "\n")

    print(f"Wrote {len(selected)} configs to {out}")


if __name__ == "__main__":
    main()

