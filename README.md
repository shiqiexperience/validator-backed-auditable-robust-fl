# Hash-Chain Auditable Robust Federated Learning

This repository is a cleaned reproducibility package for the manuscript:

**Hash-Chain Auditable Reputation-Aware Robust Aggregation for Federated Learning Against Poisoning Attacks**

The package contains the paper-specific implementation, experiment configurations, result summaries, figures, and audit-case artifacts. It intentionally excludes legacy exploratory scripts and local machine artifacts from the original development folder.

## Contents

| Path | Description |
|---|---|
| `src/research/` | Aggregation, poisoning attacks, audit-chain utilities, and metrics |
| `experiments/` | Benchmark runners, manifest generation, summarization, and export scripts |
| `configs/b_journal_suite_core_cuda/` | JSON configurations and manifests used for reported experiments |
| `results/` | Consolidated result tables, exported paper figures, and audit-case artifacts |
| `paper/` | Manuscript source, BibTeX references, and figure/table caption list |
| `docs/` | Reproducibility release plan and release manifest |

## Environment

Create and activate a Python environment, then install dependencies:

```powershell
python -m venv .venv
.\.venv\Scripts\activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

For GPU execution, install a CUDA-enabled PyTorch build that matches the local CUDA driver before running the experiments. CPU execution is supported but slower.

## Reproducing Experiments

The full experiment suite is computationally expensive. The key entry points are:

```powershell
python experiments/generate_b_journal_suite.py --suite core --profile cuda --out-dir configs\b_journal_suite_core_cuda
python experiments/run_b_journal_suite.py --manifest configs\b_journal_suite_core_cuda\core_manifest.txt
python experiments/summarize_b_journal_results.py --results-dir experiments_b_journal --out experiments_b_journal\summary_table.csv
```

For a smaller check, run a limited subset:

```powershell
python experiments/run_b_journal_suite.py --manifest configs\b_journal_suite_core_cuda\core_manifest.txt --limit 6
```

The released `results/` directory contains the consolidated summaries and figures used by the manuscript.

## Regenerating Tables and Figures

```powershell
python experiments/export_paper_tables.py
python experiments/export_paper_figures.py
python experiments/export_audit_case.py
python experiments/export_overhead_table.py
```

These scripts read the consolidated experiment outputs and regenerate the paper tables, plots, and audit-case summaries.

## Data

The experiments use public benchmark datasets: MNIST, Fashion-MNIST, and CIFAR-10. Datasets should be downloaded through the standard dataset loaders rather than redistributed in this repository.

## Notes

- The package is intended for paper reproducibility, not as a general-purpose FL framework.
- Legacy exploratory result folders, local virtual environments, caches, and machine-specific paths are intentionally excluded.
- If this package is released publicly, tag the release version that corresponds to the submitted or accepted manuscript.

## License

The code in this reproducibility package is released under the MIT License. Manuscript text and third-party datasets remain subject to their respective rights and licenses.
