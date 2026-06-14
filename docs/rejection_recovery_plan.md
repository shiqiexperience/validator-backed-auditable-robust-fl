# Rejection Recovery Plan

Date: 2026-06-14  
Rejected manuscript: JISAS-D-26-03584  
Journal: Journal of Information Security and Applications  
Title: Hash-Chain Auditable Reputation-Aware Robust Aggregation for Federated Learning Against Poisoning Attacks

## 1. Editorial Decision Summary

The manuscript was rejected for insufficient novelty and failure to meet the journal's quality standard. The decisive technical criticism was:

> If the central server is the only party calculating the scores, determining the weights, and writing blocks to the hash chain, the audit log provides zero Byzantine security against an insider threat. Expecting a single server to act as both the aggregator and the hash-chain manager is a critical security design flaw.

This is a system-model problem, not a minor writing or plotting issue.

## 2. Core Failure Mode

The submitted design treats the aggregation server as both:

1. the party that computes anomaly scores, reputations, and aggregation weights; and
2. the party that writes and maintains the hash-chain audit log.

This creates a trust collapse:

- a malicious or compromised server can fabricate scores;
- it can choose misleading aggregation weights;
- it can write a self-consistent hash chain after the fact;
- the hash chain proves only that the server committed to a record, not that the record was independently verified.

Therefore, the current hash-chain layer is best described as tamper-evident centralized logging, not Byzantine-secure auditability.

## 3. Recovery Objective

Upgrade the work from:

> centralized hash-chain logging for robust FL aggregation

to:

> role-separated, validator-backed auditable robust aggregation for poisoning-resistant federated learning

The new design must separate:

- aggregation;
- audit-record proposal;
- independent verification;
- audit-chain finalization.

## 4. Revised Threat Model

The revised paper should explicitly model:

### Malicious clients

Clients may submit poisoned model updates through sign-flip, adaptive-scaling, backdoor, or other model/data poisoning strategies.

### Potentially dishonest or faulty server

The aggregation server may:

- misreport anomaly scores;
- alter aggregation weights;
- omit client updates;
- modify model hashes;
- write an inconsistent audit block;
- attempt to hide malicious-client influence.

### Independent validators

A committee of validators or auditors maintains the audit chain. Validators are independent from the aggregation server and verify proposed audit blocks before finalization.

### Trust assumption

Security requires at least a threshold of honest validators. A reasonable first version can assume:

- `m` validators;
- at most `f` Byzantine validators;
- finality requires at least `q` valid signatures, e.g. `q = 2f + 1` or majority threshold in a simplified permissioned setting.

## 5. Revised Protocol

### Step 1: Client-signed update commitment

Each client submits:

- local update or update hash;
- client ID;
- round ID;
- sample count;
- optional metadata;
- digital signature over the commitment.

Purpose:

- the server cannot forge a client update;
- validators can check whether a proposed block corresponds to signed client submissions.

### Step 2: Server proposes aggregation decision

The server computes:

- update norm;
- direction score;
- history score;
- anomaly score;
- reputation before/after;
- hard-rejection flag;
- raw aggregation weight;
- normalized aggregation coefficient;
- model hash.

The server creates a proposed audit block but cannot finalize it alone.

### Step 3: Validator verification

Validators verify:

- client signatures;
- update/model hashes;
- hash linkage to the previous block;
- required decision fields are present;
- score and weight calculations match the public rule;
- final aggregate hash is consistent with accepted weighted updates, if full update access is available;
- or consistency of committed metadata under a lightweight verification mode.

### Step 4: Threshold finalization

An audit block is finalized only if at least `q` validators sign it. The finalized block stores:

- previous hash;
- payload hash;
- validator signatures;
- verification result;
- finalized block hash.

### Step 5: Audit reconstruction

An auditor can later verify:

- chain validity;
- threshold signatures;
- client commitment inclusion;
- decision reconstructability;
- tamper detection;
- server-side invalid block rejection.

## 6. New Experimental Validation

The existing poisoning experiments remain useful, but they are insufficient for the revised security claim. Add protocol-level security experiments.

### 6.1 Server tampering detection

Simulate a dishonest server modifying:

- anomaly scores;
- aggregation weights;
- malicious/benign labels in audit payload;
- model hash;
- previous hash;
- omitted client records.

Metrics:

- tamper detection rate;
- invalid block rejection rate;
- false rejection of valid blocks.

### 6.2 Decision verification

Validators recompute score and weight fields from stored evidence.

Metrics:

- decision verification rate;
- decision reconstruction rate;
- mismatch localization rate.

### 6.3 Threshold sensitivity

Vary:

- number of validators, e.g. 3, 5, 7;
- signing threshold, e.g. majority or `2f + 1`;
- Byzantine validator fraction.

Metrics:

- finalization success rate;
- invalid block acceptance rate;
- audit finality latency;
- verification overhead.

### 6.4 Audit overhead

Compare:

- centralized hash-chain logging;
- validator-backed audit chain with 3/5/7 validators.

Metrics:

- verification time per round;
- additional storage per block;
- signature overhead;
- total audit log size.

## 7. Code Changes Needed

Add a new module:

- `src/research/validator_audit.py`

Core components:

- `ClientCommitment`
- `Validator`
- `ValidatorCommittee`
- `ProposedAuditBlock`
- `FinalizedAuditBlock`
- signature simulation or real Ed25519 signatures
- block verification routines
- tampering scenarios

Add experiment script:

- `experiments/export_validator_audit_metrics.py`

Outputs:

- `experiments_b_journal/paper_tables/validator_audit_metrics.csv`
- `experiments_b_journal/paper_tables/validator_threshold_sensitivity.csv`
- possible figure: `validator_audit_overhead.pdf`

## 8. Manuscript Changes Needed

### Title

Possible revised title:

> Validator-Backed Hash-Chain Auditable Robust Aggregation for Federated Learning Against Poisoning and Server-Side Tampering

### Abstract

Must mention:

- role separation;
- validator-backed audit finalization;
- poisoning attacks and server-side tampering;
- objective auditability metrics.

### Introduction

Add the gap:

> Existing hash-chain or blockchain-assisted FL schemes often log training events, but if the aggregation server alone constructs and finalizes the log, the audit trail does not protect against insider manipulation.

### Threat Model

Add dishonest/faulty server and validator trust assumptions.

### Method

Replace single-server audit-chain logging with:

- server-proposed audit block;
- validator verification;
- threshold-signed finalization.

### Experiments

Add:

- server tampering simulation;
- invalid block rejection;
- threshold sensitivity;
- validator overhead.

### Limitations

Clarify:

- full permissioned blockchain consensus is still not implemented unless actually implemented;
- validator independence is a deployment assumption;
- cryptographic verification adds overhead;
- privacy-preserving verification may require secure aggregation or zero-knowledge methods in future work.

## 9. Target Venue Strategy

Do not appeal the JISA rejection. The editor's criticism is direct and fundamental.

Recommended path:

1. build the validator-backed revision;
2. generate new protocol-security experiments;
3. update manuscript;
4. then choose a new venue.

Potential venue classes:

- applied cybersecurity journals;
- distributed systems/security journals;
- blockchain-assisted computing journals;
- federated learning security special issues.

The next venue should be selected only after the revised contribution is clear.

## 10. Immediate Next Steps

1. Implement validator-backed audit simulation.
2. Generate server-tampering and validator-verification metrics.
3. Add one compact protocol-security table and one overhead table/figure.
4. Rewrite Threat Model and Proposed Method.
5. Reframe novelty around role separation and validator-backed audit finalization.

