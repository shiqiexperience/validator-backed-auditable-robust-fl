"""Run a generated B-journal experiment suite manifest sequentially."""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]


def read_manifest(path: Path):
    with open(path, "r", encoding="utf-8-sig") as handle:
        return [line.strip().lstrip("\ufeff") for line in handle if line.strip()]


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--limit", type=int, default=None, help="Run only the first N configs.")
    args = parser.parse_args()

    configs = read_manifest(Path(args.manifest))
    if args.limit is not None:
        configs = configs[: args.limit]

    for idx, config in enumerate(configs, start=1):
        print(f"[{idx}/{len(configs)}] Running {config}")
        cmd = [sys.executable, str(PROJECT_ROOT / "experiments" / "robust_benchmark.py"), "--config", config]
        result = subprocess.run(cmd, cwd=str(PROJECT_ROOT))
        if result.returncode != 0:
            raise SystemExit(f"Experiment failed: {config}")


if __name__ == "__main__":
    main()
