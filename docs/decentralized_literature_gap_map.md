# Decentralized and Blockchain-Assisted FL: Challenge Map and Revision Targets

Date: 2026-06-14

## Purpose

This note summarizes recent decentralized federated learning (DFL) and blockchain-assisted FL literature and maps recurring open problems to concrete improvements for the revised manuscript.

The goal is not to claim that blockchain automatically solves poisoning. The revised paper should argue more carefully:

> Removing the central server solves one trust bottleneck, but it creates new verification, consensus, privacy, and scalability problems. The proposed protocol targets the specific problem of auditable robust aggregation under malicious clients and potentially dishonest round aggregators.

## Evidence Landscape

### Established direction

- Biscotti and BlockDFL show that fully decentralized or peer-to-peer FL can be coordinated through a ledger/blockchain layer.
- BLADE-FL and related blockchain-assisted FL work frame blockchain as a way to reduce reliance on a central aggregation server.
- Surveys on DFL and BlockFL repeatedly identify server removal, direct client coordination, transparency, and auditability as motivations for decentralization.

### Recent direction

- DFL security surveys emphasize that removing the server also introduces new attack surfaces and privacy concerns.
- Recent poisoning work on DFL shows that decentralized propagation can create new collusive model-poisoning strategies, not just remove old centralized risks.
- Recent blockchain-FL proposals increasingly combine robust aggregation, consensus, judge/validator models, clustering, incentive design, and on-chain/off-chain benchmarking.

## Recurring Problems in Recent Literature

### 1. Trust shifts from server to validators or miners

Decentralization removes the single aggregation server, but trust does not disappear. It moves to consensus participants, miners, validators, oracle nodes, or committees. If the validating quorum is malicious, invalid aggregation decisions can still be finalized.

Implication for our paper:

- Do not claim unconditional Byzantine security.
- Explicitly state the threshold assumption.
- Add an experiment showing the safe region and the failure region.

Implemented response:

- Added `validator_audit_byzantine_boundary.csv`.
- Under 5 validators and threshold 3:
  - 0, 1, or 2 Byzantine validators: invalid proposal rejection rate = 100%.
  - 3 Byzantine validators: invalid proposal acceptance rate = 100%.
- Under 7 validators and threshold 5:
  - 2 or 4 Byzantine validators: invalid proposal rejection rate = 100%.
  - 5 Byzantine validators: invalid proposal acceptance rate = 100%.

This is useful because it turns a possible reviewer criticism into a measured threat-model boundary.

### 2. Consensus and verification overhead

BlockFL surveys emphasize that overhead and compatibility remain important unresolved issues. Decentralized FL may reduce central-server bottlenecks but can add validator verification, block propagation, signatures, consensus latency, and storage overhead.

Implication for our paper:

- Report verification latency separately from training time.
- Keep full model updates off-chain; store commitments, hashes, scores, decisions, and finality signatures.
- Compare 3/5/7 validators and different thresholds.

Implemented response:

- Added threshold sensitivity:
  - 3 validators / threshold 2: about 0.79 ms per valid block.
  - 5 validators / threshold 3: about 1.31-1.59 ms per valid block depending on table/run timing.
  - 7 validators / threshold 4 or 5: about 1.84-2.28 ms per valid block.

Remaining improvement:

- Add storage-overhead breakdown for validator signatures and aggregator signatures.

### 3. Non-IID data can resemble malicious behavior

DFL and robust aggregation surveys repeatedly identify heterogeneity as a central challenge. Distance-based filters and fixed thresholds can reject legitimate Non-IID updates. Recent Byzantine-robust DFL work also treats Non-IID false rejection as a key scalability and validity problem.

Implication for our paper:

- Keep benign-retention metrics.
- Report malicious suppression and benign retention together.
- Avoid claiming that every rejected update is truly malicious.

Implemented response:

- Existing audit metrics already include benign retention and malicious suppression.
- Proposed aggregation records norm, direction, history, reputation, rejection flag, and aggregation weight so the reason for each suppression can be inspected.

Remaining improvement:

- Add a Non-IID severity sensitivity experiment if time permits, e.g. Dirichlet alpha in `{0.1, 0.3, 0.5, 1.0}` for proposed vs baselines.

### 4. Decentralization introduces new poisoning channels

Recent DFL poisoning work argues that decentralized model propagation enables attacks that differ from centralized global-model poisoning. Collusive participants can exploit differences between neighbor models or local model states.

Implication for our paper:

- Current sign-flip, adaptive-scaling, and backdoor attacks are useful but do not fully cover DFL-specific poisoning.
- The revised paper should either add a DFL-specific collusion/tampering experiment or clearly state it as future work.

Possible targeted experiment:

- Simulate collusive aggregators or validators attempting to finalize altered proposals.
- Simulate model-difference poisoning by allowing malicious clients to craft updates close to benign norm statistics but directionally harmful.

Implemented partial response:

- Added aggregator-side tampering scenarios:
  - unauthorized aggregator;
  - aggregator signature tampering;
  - equivocation-style proposal tampering.

Remaining improvement:

- Add a collusive-client DFL poisoning scenario only if it can be implemented cleanly and compared against baselines.

### 5. Privacy leakage through audit logs

DFL security surveys emphasize that model-update exchange and ledger records can create new privacy surfaces. An immutable audit log is useful for accountability but risky if it stores sensitive update details.

Implication for our paper:

- Do not store raw model updates on chain.
- Store hashes, commitments, aggregate statistics, and decision evidence.
- State that privacy-preserving verification may require secure aggregation, homomorphic encryption, TEEs, or zero-knowledge proofs in future deployment.

Implemented response:

- Validator audit simulation uses update hashes and metadata commitments.

Remaining improvement:

- Add a paragraph in limitations explaining that the current protocol is audit-focused, not a full privacy-preserving verification scheme.

### 6. Identity, permissioning, and Sybil resistance

Open decentralized systems must handle Sybil identities, validator admission, and incentive compatibility. Permissioned systems avoid some Sybil problems but require governance assumptions.

Implication for our paper:

- Frame the current system as permissioned or consortium FL.
- Avoid open-public-blockchain claims.
- State that validator identity and membership are managed by the consortium.

Implemented response:

- Current design uses permissioned validators and aggregators.

Remaining improvement:

- Add validator/aggregator membership assumptions explicitly to the threat model.

## Recommended Revised Research Position

The paper should be reframed as follows:

> Existing robust FL methods focus on model utility under malicious clients, while many blockchain-assisted FL systems emphasize logging or coordination. A missing piece is objective, validator-backed finalization of the robust aggregation decision itself under both malicious clients and potentially dishonest aggregators. We address this by combining multi-signal robust aggregation with rotating aggregator authorization, client commitments, threshold validator finality, and auditability metrics.

This is stronger than the rejected manuscript because the blockchain layer is no longer decorative logging. It performs a security role: preventing a single aggregation actor from unilaterally finalizing the evidence ledger.

## Near-Term Revision Checklist

1. Rewrite the title, abstract, and introduction around decentralized validator-backed finality.
2. Replace the single-server threat model with:
   - malicious clients;
   - dishonest rotating aggregators;
   - Byzantine validators below/above threshold;
   - permissioned membership assumption.
3. Add new protocol-security table:
   - valid finalization rate;
   - invalid proposal rejection rate;
   - aggregator authorization verification rate;
   - invalid acceptance rate;
   - verification latency.
4. Add Byzantine-boundary table:
   - show safe-region and failure-region results.
5. Add limitation paragraph:
   - not full production blockchain;
   - not a complete privacy-preserving verification protocol;
   - validator collusion beyond threshold breaks finality;
   - DFL-specific collusive model-difference poisoning remains future work unless implemented.

## Sources to Re-check Before Submission

The following recent items are useful for direction setting but must be rechecked before final submission to see whether a peer-reviewed version exists:

- FIDELIS, 2025.
- Krum Federated Chain, 2025.
- DMPA, 2025.
- ABC-DFL, 2026.
- Spectral Sentinel, 2025.

