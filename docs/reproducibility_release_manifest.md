# Reproducibility Release Manifest

This manifest defines the recommended contents of a cleaned paper-specific repository. It separates final reproducibility assets from legacy exploratory code.

Recommended repository name:

`hashchain-auditable-robust-fl`

## Include: Core Code

| Source path | Release path | Required |
|---|---|---|
| `src/research/__init__.py` | `src/research/__init__.py` | Yes |
| `src/research/aggregation.py` | `src/research/aggregation.py` | Yes |
| `src/research/attacks.py` | `src/research/attacks.py` | Yes |
| `src/research/audit.py` | `src/research/audit.py` | Yes |
| `src/research/metrics.py` | `src/research/metrics.py` | Yes |

## Include: Experiment Scripts

| Source path | Release path | Required |
|---|---|---|
| `experiments/robust_benchmark.py` | `experiments/robust_benchmark.py` | Yes |
| `experiments/generate_b_journal_suite.py` | `experiments/generate_b_journal_suite.py` | Yes |
| `experiments/run_b_journal_suite.py` | `experiments/run_b_journal_suite.py` | Yes |
| `experiments/summarize_b_journal_results.py` | `experiments/summarize_b_journal_results.py` | Yes |
| `experiments/export_paper_tables.py` | `experiments/export_paper_tables.py` | Yes |
| `experiments/export_paper_figures.py` | `experiments/export_paper_figures.py` | Yes |
| `experiments/export_audit_case.py` | `experiments/export_audit_case.py` | Yes |
| `experiments/export_overhead_table.py` | `experiments/export_overhead_table.py` | Yes |
| `experiments/make_pilot_manifest.py` | `experiments/make_pilot_manifest.py` | Optional |

## Include: Final Configurations

| Source path | Release path | Required |
|---|---|---|
| `configs/b_journal_suite_core_cuda/core_manifest.txt` | `configs/b_journal_suite_core_cuda/core_manifest.txt` | Yes |
| `configs/b_journal_suite_core_cuda/core_*.json` | `configs/b_journal_suite_core_cuda/` | Yes |
| `configs/b_journal_suite_core_cuda/core_ratio_*.json` | `configs/b_journal_suite_core_cuda/` | Yes |
| `configs/b_journal_suite_core_cuda/fashion_ratio_sensitivity18.txt` | `configs/b_journal_suite_core_cuda/fashion_ratio_sensitivity18.txt` | Yes |
| `configs/b_journal_suite_core_cuda/cifar10_noniid_seed43_main18.txt` | `configs/b_journal_suite_core_cuda/cifar10_noniid_seed43_main18.txt` | Optional |
| `configs/b_journal_suite_core_cuda/cifar10_noniid_seed44_main18.txt` | `configs/b_journal_suite_core_cuda/cifar10_noniid_seed44_main18.txt` | Optional |
| `configs/b_journal_suite_core_cuda/cifar10_seed42_main36.txt` | `configs/b_journal_suite_core_cuda/cifar10_seed42_main36.txt` | Optional |

## Include: Result Summaries and Paper Artifacts

| Source path | Release path | Required |
|---|---|---|
| `experiments_b_journal/summary_table.csv` | `results/summary_table.csv` | Yes |
| `experiments_b_journal/ratio_sensitivity_summary.csv` | `results/ratio_sensitivity_summary.csv` | Yes |
| `experiments_b_journal/paper_tables/` | `results/paper_tables/` | Yes |
| `experiments_b_journal/paper_figures/` | `results/paper_figures/` | Yes |
| `experiments_b_journal/audit_case/fashion_noniid_signflip_proposed_s42/` | `results/audit_case/fashion_noniid_signflip_proposed_s42/` | Yes |

## Include: Manuscript Support

| Source path | Release path | Required |
|---|---|---|
| `docs/manuscript_jisa.tex` | `paper/manuscript_jisa.tex` | Optional |
| `docs/references.bib` | `paper/references.bib` | Optional |
| `docs/figure_caption_list_jisa.md` | `paper/figure_caption_list_jisa.md` | Optional |
| `docs/reproducibility_release_plan.md` | `docs/reproducibility_release_plan.md` | Yes |

## Create for Release

These files should be created in the cleaned repository:

| Release path | Purpose |
|---|---|
| `README.md` | Installation, reproduction commands, dataset notes, expected outputs |
| `requirements.txt` | Python dependencies |
| `.gitignore` | Exclude datasets, virtual environments, caches, raw logs |
| `LICENSE` | Selected open-source license |
| `CITATION.cff` | Citation metadata after title/authors are final |

## Exclude

Do not include these in the public reproducibility repository:

- `venv_cuda/` or any local virtual environment.
- `__pycache__/`, `.pytest_cache/`, LaTeX auxiliary files, local editor files.
- Legacy result folders under `experiments/MNIST_iid_clients10_*`.
- Early scripts not used in the paper, such as older testing and text-generation scripts, unless explicitly documented.
- Smoke-test configs unless needed for a quick-start demo.
- Raw downloaded datasets if licenses require users to download them from official sources.
- Any personal notes, credentials, local absolute paths, or account information.

## Release Recommendation

Prepare the cleaned repository privately first. Make it public at acceptance or before submission only after the README, dependency file, and reproduction commands have been tested on a clean environment.
