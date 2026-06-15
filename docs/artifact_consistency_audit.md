# Artifact Consistency Audit

Date: 2026-06-15

This note records the consistency checks performed for the reproducibility package of:

`Validator-Backed Auditable Robust Aggregation for Secure Networked Federated Learning`

## Scope

The audit checked whether the public artifact package is aligned with the current manuscript, result tables, figure files, and reproduction instructions. It did not re-run the full training suite.

## Checked Items

| Item | Status | Evidence |
|---|---|---|
| Current manuscript title in README and citation metadata | Pass | `README.md`, `CITATION.cff` |
| Earlier venue-specific manuscript files removed from public package | Pass | `paper/` contains only `manuscript_comnet.*` and `references.bib` |
| Core method code updated | Pass | `src/research/aggregation.py`, `src/research/validator_audit.py` |
| Current experiment scripts updated | Pass | `experiments/robust_benchmark.py`, `experiments/generate_b_journal_suite.py`, `experiments/export_paper_tables.py`, `experiments/export_validator_audit_metrics.py` |
| Main result tables present | Pass | `results/paper_tables/formal_latest_results.csv`, `fashionmnist_main_table.csv`, `cifar10_noniid_main_table.csv` |
| Extension baselines present | Pass | `fltrust_extension_table.csv`, `flame_backdoor_extension_table.csv`, `collusive_extension_table.csv` |
| Sensitivity and ablation outputs present | Pass | `sensitivity_latest_results.csv`, `coefficient_sensitivity_table.csv`, `proposed_ablation_table.csv` |
| Validator-audit outputs present | Pass | `validator_audit_*.csv` tables under `results/paper_tables/`, including event-driven finality outputs |
| Paper figures present | Pass | `results/paper_figures/*.pdf` and audit-case figures under `results/audit_case/` |
| Manuscript figure paths compile inside release package | Pass | `paper/manuscript_comnet.tex` uses `../results/...` paths |
| Auxiliary LaTeX files excluded | Pass | No `.aux`, `.log`, `.bbl`, `.blg`, or `.spl` retained |

## Verification Commands Run

```powershell
python experiments/export_paper_tables.py --summary results\summary_table.csv --out-dir results\paper_tables
python experiments/export_paper_figures.py --tables-dir results\paper_tables --out-dir results\paper_figures
pdflatex -interaction=nonstopmode -halt-on-error manuscript_comnet.tex
bibtex manuscript_comnet
pdflatex -interaction=nonstopmode -halt-on-error manuscript_comnet.tex
pdflatex -interaction=nonstopmode -halt-on-error manuscript_comnet.tex
```

The manuscript compiled to a 42-page PDF from within the release package, with no undefined-reference, undefined-citation, overfull-box, or LaTeX error warnings in the final log scan. The supplementary tables compiled to a 5-page PDF and include S4, which documents the event-driven finality simulation parameters.

## Notes

`experiments_b_journal/` remains as a legacy run-output directory name in several scripts and configuration files. It is retained for backward compatibility with existing experiment manifests and raw run outputs. It does not refer to the current manuscript venue or scope.

The released `overhead_table.csv`, validator-audit tables, and `validator_audit_network_events_summary.csv` depend on raw run-level timing and audit records. They are included in `results/paper_tables/`; regenerating them from scratch requires reproducing the raw run directories first.
