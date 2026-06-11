# Audit Case Study

## Run

- Run directory: `experiments_b_journal\core_fashionmnist_noniid_sign_flip_proposed_s42_20260607_101012`
- Dataset: FashionMNIST
- Data split: Non-IID (alpha=0.5)
- Attack: sign_flip
- Aggregation: proposed
- Seed: 42
- Rounds: 80
- Final clean accuracy: 86.47%
- Best clean accuracy: 86.47%
- Final ASR: 1.08%
- Chain linkage valid: True
- Stored audit blocks: 80

## Client-Level Audit Summary

- Malicious clients: 2
- Benign clients: 8
- Mean aggregation weight, malicious clients: 0.0000
- Mean aggregation weight, benign clients: 0.2831
- Mean zero-weight rounds, malicious clients: 80.0
- Mean zero-weight rounds, benign clients: 11.4

## Interpretation

This case illustrates the audit function of the proposed method. The two sign-flip attackers receive near-zero mean aggregation weight across rounds, while benign clients retain nonzero contribution weights. The audit chain records per-round model hashes, metrics, client update metadata, aggregation weights, and block hashes, allowing later reconstruction of why a client update affected or did not affect the global model.

The case should be used as qualitative evidence of traceability and decision reconstruction. It should not be presented as standalone proof of malicious-client detection performance; aggregate accuracy and ASR claims should rely on the main tables.

## Generated Artifacts

- `audit_case_round_metrics.png/.pdf`
- `audit_case_client_weights.png/.pdf`
- `client_audit_summary.csv`
- `audit_chain_excerpt.csv`
