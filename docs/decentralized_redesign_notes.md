# Decentralized Redesign Notes

Date: 2026-06-14

## Motivation

The JISA rejection identified a fundamental flaw in the submitted design: the same central server computed anomaly scores, determined aggregation weights, and wrote the hash-chain audit log. Under an insider threat, such a server can fabricate a self-consistent log. A hash chain then proves only that a record is internally linked, not that the aggregation decision was independently verified.

The revised direction should therefore remove the permanently trusted central server assumption. The stronger claim is not that the system has no coordination role at all, but that no single coordinator can both decide and finalize the audit record.

## Literature Basis

Decentralized and blockchain-assisted FL is an established research direction.

- Biscotti proposes a fully decentralized peer-to-peer learning ledger to avoid reliance on trusted centralized infrastructure while addressing poisoning and privacy risks.
- BLADE-FL integrates blockchain into decentralized FL because standard FL is vulnerable to server malfunction, untrustworthy servers, and external attacks.
- BlockDFL explicitly frames fully decentralized peer-to-peer FL as a way to remove central dependence, while using PBFT-style voting and scoring to coordinate untrusted participants and defend against poisoning.
- Recent blockchain-assisted FL studies and surveys also emphasize transparency, accountability, tamper resistance, and decentralized coordination as major reasons to introduce blockchain into FL.

These works justify shifting the manuscript from "centralized robust FL with hash-chain logging" to "decentralized validator-backed auditable robust FL".

## Revised Core Claim

Recommended new claim:

> We propose a decentralized validator-backed auditable robust aggregation protocol in which a round-specific aggregator proposes the robust FL decision, while independent validators verify client commitments, aggregator authorization, score/weight consistency, hash linkage, and block finality before the decision becomes part of the audit chain.

This directly addresses the rejection:

- the aggregator cannot finalize its own audit log;
- validators independently check the proposed decision;
- a legal block requires threshold signatures;
- an unauthorized or tampered proposal is rejected before finality;
- the audit chain becomes a threshold-finalized evidence ledger rather than a single-server log.

## Proposed Protocol

### 1. Client commitment

Each participating client signs a commitment containing:

- round ID;
- client ID;
- update hash;
- sample count;
- metadata hash.

This prevents a malicious aggregator from inventing client submissions or silently changing committed metadata.

### 2. Rotating aggregator selection

For each round, a public rule selects an eligible aggregator from a permissioned committee. The current implementation uses deterministic round-robin selection:

```text
aggregator_t = sorted(aggregators)[(t - 1) mod m]
```

This is intentionally simple and reproducible. In a full blockchain deployment, this can be replaced by stake-weighted selection, VRF-based leader election, PBFT leader rotation, or smart-contract scheduling.

### 3. Aggregation proposal

The selected aggregator computes:

- anomaly scores;
- reputation updates;
- rejection/down-weighting decisions;
- aggregation weights;
- model and payload hashes.

It signs the proposal, but this signature alone is not enough for finality.

### 4. Validator verification

Validators check:

- client signatures;
- payload hash;
- proposal hash;
- previous-block linkage;
- required score and reputation fields;
- client/decision/commitment set consistency;
- aggregation-weight consistency;
- aggregator eligibility for the round;
- aggregator signature.

### 5. Threshold finalization

A block is finalized only if at least `q` validators sign it. The finalized block contains:

- round ID;
- previous hash;
- payload hash;
- proposal hash;
- validator signatures;
- rejected validator votes;
- final block hash.

## New Protocol Experiments

The updated experiment script is:

```powershell
D:\code\python_project\blockchain_federated_learning\venv_cuda\Scripts\python.exe experiments\export_validator_audit_metrics.py
```

It reuses existing audit logs and evaluates the validator-backed decentralized audit protocol over the latest proposed runs.

Generated tables:

- `experiments_b_journal/paper_tables/validator_audit_tamper_by_scenario.csv`
- `experiments_b_journal/paper_tables/validator_audit_tamper_per_run.csv`
- `experiments_b_journal/paper_tables/validator_audit_valid_blocks.csv`
- `experiments_b_journal/paper_tables/validator_audit_threshold_sensitivity.csv`

Current results:

- Proposed runs evaluated: 39
- Valid audit blocks checked: 3600
- Tampered/invalid proposal checks: 43200
- Valid block finalization rate: 100%
- Aggregator authorization verification rate: 100%
- Invalid proposal rejection rate: 100%
- Invalid proposal acceptance rate: 0%
- Mean valid verification time with 5 validators and threshold 3: about 1.32 ms per block

Tampering and protocol-fault scenarios:

- score tampering;
- aggregation-weight tampering;
- client-side weight tampering;
- model-hash tampering;
- previous-hash tampering;
- omitted client;
- fake client;
- client signature tampering;
- payload-hash tampering;
- unauthorized aggregator;
- aggregator signature tampering;
- aggregator equivocation-style proposal tampering.

Threshold sensitivity:

- 3 validators / threshold 2 / 0 Byzantine validators: valid finalization 100%, invalid rejection 100%.
- 5 validators / threshold 3 / 0 Byzantine validators: valid finalization 100%, invalid rejection 100%.
- 7 validators / threshold 4 / 0 Byzantine validators: valid finalization 100%, invalid rejection 100%.
- 5 validators / threshold 3 / 1 Byzantine validator: valid finalization 100%, invalid rejection 100%.
- 7 validators / threshold 5 / 2 Byzantine validators: valid finalization 100%, invalid rejection 100%.

## Manuscript Restructuring Needed

The old manuscript still reads as a single-server audit-chain design. It should be rewritten before resubmission.

Required changes:

1. Title should mention decentralized or validator-backed finalization.
2. Abstract must state that a rotating aggregator proposes blocks and validators finalize them.
3. Threat model must include malicious clients, dishonest aggregators, and Byzantine validators.
4. Method section must replace "the server records the audit chain" with a proposal-verification-finalization protocol.
5. Experiments must include server/aggregator tampering, unauthorized proposer rejection, threshold sensitivity, and verification overhead.
6. Limitations must state that the current implementation is a permissioned protocol simulation, not a production blockchain with real consensus networking, incentives, gas accounting, or privacy-preserving verification.

## Recommended New Title

Possible title:

> Decentralized Validator-Backed Auditable Robust Aggregation for Federated Learning Against Poisoning and Aggregator Tampering

This title is stronger than the rejected version because it moves the contribution from simple hash-chain logging to role-separated finalization under an explicit dishonest-aggregator threat model.

