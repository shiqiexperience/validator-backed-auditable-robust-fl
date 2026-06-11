# Reproducibility Release Plan

Recommended decision: release a cleaned, paper-specific reproducibility package rather than publishing the full legacy project folder.

## Rationale

The current project contains early exploratory code, smoke tests, tuning attempts, generated artifacts, and paper-specific scripts. Publishing the full folder would make the contribution harder to inspect and may expose obsolete code paths that are not part of the final manuscript. A separate release package is cleaner for reviewers and better aligned with reproducible research.

## Recommended Repository Scope

Suggested repository name:

`hashchain-auditable-robust-fl`

Detailed include/exclude rules are maintained in `docs/reproducibility_release_manifest.md`.

Suggested contents:

| Path | Content |
|---|---|
| `src/research/` | Final aggregation, attack, audit, and metric logic used by the paper |
| `experiments/robust_benchmark.py` | Main benchmark runner |
| `experiments/generate_b_journal_suite.py` | Config/manifest generator |
| `experiments/run_b_journal_suite.py` | Manifest runner |
| `experiments/summarize_b_journal_results.py` | Result summarization |
| `experiments/export_paper_tables.py` | Paper table export |
| `experiments/export_paper_figures.py` | Paper figure export |
| `experiments/export_audit_case.py` | Audit case export |
| `experiments/export_overhead_table.py` | Overhead table export |
| `configs/` | Final reproducibility manifests and JSON configs used for reported experiments |
| `docs/` | Manuscript, references, result tables, and figure captions |
| `README.md` | Installation, dataset preparation, GPU/CPU instructions, and reproduction commands |
| `requirements.txt` or `environment.yml` | Exact dependency specification |
| `LICENSE` | License selected by the author |

## Exclude From Public Release

- Early abandoned scripts not used in the paper.
- Local virtual environments such as `venv_cuda/`.
- Raw cache folders and downloaded datasets unless licensing permits redistribution.
- Personal notes, account information, machine-specific paths, and editor files.
- Duplicate smoke-test outputs and failed tuning logs unless needed for transparency.
- Any file containing API keys, personal identifiers, or private collaboration notes.

## Data and Artifact Strategy

Public datasets should be downloaded by script or documented through standard sources. Generated result summaries, final figures, and selected audit logs can be included if file size is manageable. Large raw experiment logs can be deposited on Zenodo, OSF, Figshare, or a release asset if needed.

## Manuscript Data Availability Wording

Recommended current wording:

> The experiments use public benchmark datasets, including MNIST, Fashion-MNIST, and CIFAR-10. A cleaned paper-specific reproducibility package containing the code, configurations, result summaries, and analysis scripts will be made available in a public repository upon publication or from the corresponding author upon reasonable request.

If the repository is made public before submission, replace the final sentence with the repository URL and, ideally, an archived DOI.

## Release Timing

Best option for a B-journal submission:

1. Prepare a private cleaned repository before submission.
2. Include the data/code availability statement in the manuscript.
3. Make the repository public at acceptance or earlier if the supervisor agrees.
4. Tag a release matching the submitted/accepted manuscript.

Earlier public release can improve transparency, but only do this after removing legacy code, local paths, and unnecessary artifacts.
