# GitHub Upload Checklist

Use this checklist before pushing the reproducibility package to GitHub.

## Include

- `README.md`, `LICENSE`, `CITATION.cff`, `.gitignore`, `requirements.txt`.
- `src/research/` with the paper-specific implementation.
- `experiments/` with benchmark, summarization, table, figure, and validator-audit export scripts.
- `configs/` with the reported experiment manifests and JSON configurations.
- `results/summary_table.csv`, `results/ratio_sensitivity_summary.csv`.
- `results/paper_tables/`, including validator-audit and event-driven finality CSV files.
- `results/paper_figures/` and `results/audit_case/`.
- `paper/manuscript_comnet.tex`, `paper/manuscript_comnet.pdf`, `paper/supplementary_tables_comnet.tex`, `paper/supplementary_tables_comnet.pdf`, and `paper/references.bib`.
- `docs/` release notes and reproducibility documentation.

## Exclude

- Local environments: `.venv/`, `venv/`, `venv_cuda/`.
- Downloaded datasets or caches: `data/`, `datasets/`, `downloads/`.
- Raw run directories unless intentionally archived separately: `experiments_b_journal/`.
- LaTeX auxiliary files: `.aux`, `.log`, `.bbl`, `.blg`, `.out`, `.spl`, `.toc`, `.lof`, `.lot`, `.synctex.gz`.
- Editor/cache directories: `.idea/`, `.vscode/`, `__pycache__/`, `.pytest_cache/`.
- Editorial-system files such as cover letters, competing-interest forms, reviewer responses, and submission screenshots.
- Personal notes, credentials, local absolute paths, account information, or private collaboration notes.

## Local Verification

From the repository root:

```powershell
python experiments/export_paper_tables.py --summary results\summary_table.csv --out-dir verify_paper_tables
python experiments/export_paper_figures.py --tables-dir verify_paper_tables --out-dir verify_paper_figures
```

From `paper/`:

```powershell
pdflatex -interaction=nonstopmode -halt-on-error manuscript_comnet.tex
bibtex manuscript_comnet
pdflatex -interaction=nonstopmode -halt-on-error manuscript_comnet.tex
pdflatex -interaction=nonstopmode -halt-on-error manuscript_comnet.tex
pdflatex -interaction=nonstopmode -halt-on-error supplementary_tables_comnet.tex
```

After verification, remove temporary `verify_paper_tables/`, `verify_paper_figures/`, and LaTeX auxiliary files before committing.

## Recommended Commit

```powershell
git status --short
git add README.md requirements.txt .gitignore CITATION.cff LICENSE src experiments configs results paper docs
git status --short
git commit -m "Prepare reproducibility package for validator-backed auditable FL"
git push origin main
```

If the default branch is not `main`, replace `main` with the branch shown by `git branch --show-current`.
