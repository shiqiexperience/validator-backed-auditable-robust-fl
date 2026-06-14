# Validator Committee Design Review

Date: 2026-06-14

## Purpose

This note reviews committee-based validator mechanisms that are relevant to the revised decentralized auditable FL design. It focuses on what existing mechanisms solve, what weaknesses they introduce, and which design elements we should borrow or explicitly delimit.

## Related Mechanisms

### BFLC: committee consensus for blockchain-based FL

BFLC proposes a blockchain-based FL framework with committee consensus. Its motivation is close to ours: centralized FL can be attacked through malicious clients or central servers, and committee consensus can reduce consensus cost while maintaining decentralized model storage and update exchange.

What to borrow:

- Use a committee rather than all nodes for every finality decision.
- Treat committee consensus as an efficiency/security tradeoff.
- Discuss scalability, storage optimization, and incentives as first-class system issues.

What remains risky:

- Committee security depends on how members are selected.
- A small committee improves efficiency but increases capture probability if adversaries can influence selection.

### VBFL: validator-based model validation with PoS-inspired consensus

VBFL introduces decentralized validation of local model updates and a proof-of-stake-inspired consensus mechanism. Its key idea is that individual validators examine model legitimacy, and honest behavior increases future block influence.

What to borrow:

- Validators should not merely sign hashes; they should verify model/update legitimacy evidence.
- Validator behavior can be tied to reputation, stake, or reward probability.
- Dishonest or low-quality validation should reduce future influence.

What remains risky:

- Stake or reputation can centralize influence.
- PoS-style selection can create long-term dominance by already trusted or wealthy validators.
- Incentive-compatible validation is harder than simple threshold signing.

### BFT consensus literature

Classical BFT systems provide safety and liveness only under explicit fault bounds. The common permissioned setting uses `n >= 3f + 1` replicas to tolerate `f` Byzantine faults. Modern protocols such as PBFT, Tendermint/CometBFT, HotStuff, and related variants improve performance and responsiveness, but communication and serialization costs remain scalability bottlenecks.

What to borrow:

- State the committee fault model mathematically.
- Separate safety from liveness.
- Include leader/aggregator equivocation and invalid proposal rejection.
- Report verification/finality overhead as validator count changes.

What remains risky:

- Threshold signatures alone do not prove the underlying aggregation value is correct unless validators recompute or verify the decision rule.
- BFT consensus can agree on an invalid value if enough validators approve it or if the application-level validity predicate is weak.
- Large committees can become slow due to communication, serialization, and verification overhead.

### PoS and committee-selection attacks

PoS and committee-based systems face well-known concerns: concentration of influence, long-range attacks, nothing-at-stake behavior, bribery, selfish validation, and Sybil attacks when identity generation or committee admission is cheap.

What to borrow:

- Use permissioned identities for the current paper instead of claiming open permissionless security.
- Avoid stake-only selection as the only defense.
- Include validator accountability through signed votes.
- Treat conflicting signatures as slashable or reputation-reducing evidence.

What remains risky:

- Without a concrete membership authority or admission protocol, the validator set is assumed rather than secured.
- Without penalties, validators may sign lazily or sign multiple conflicting proposals.

## Defects in Our Current Mechanism

The current implementation is a useful protocol simulation, but it is not yet a complete blockchain consensus implementation.

### 1. Static validator committee

Current state:

- Validator identities are fixed in the experiment.
- The committee is not sampled or rotated.

Risk:

- A static committee can be targeted or captured over time.

Improvement:

- Frame the current paper as permissioned consortium FL.
- Add future work or optional extension: rotating validator subsets selected from a larger permissioned pool.

### 2. Simple threshold finality

Current state:

- A block finalizes when at least `q` validators accept and sign.

Risk:

- This models finality but not full PBFT/HotStuff/Tendermint message flow.
- It captures safety under threshold assumptions, but does not model network delays, view changes, or liveness failure.

Improvement:

- Call it "threshold validator finalization" or "permissioned validator-backed finality", not full PBFT.
- Add a limitation that networking, view-change, and mempool ordering are outside the current implementation.

### 3. No liveness failure model

Current state:

- Validators can now be configured as online or offline in the protocol simulation.

Risk:

- Real committees may include offline validators or stragglers.
- A valid block may fail to finalize if too few honest validators respond before timeout.

Improvement:

- Add a liveness/dropout sensitivity experiment:
  - vary offline validators;
  - measure valid finalization rate;
  - show the condition `available honest validators >= threshold`.

Implemented result:

- Output table: `experiments_b_journal/paper_tables/validator_audit_liveness_dropout.csv`.
- With 5 validators and threshold 3:
  - 0, 1, or 2 offline validators: valid finalization rate = 100%.
  - 3 offline validators: valid finalization rate = 0%.
- With 7 validators and threshold 5:
  - 0, 1, or 2 offline validators: valid finalization rate = 100%.
  - 3 offline validators: valid finalization rate = 0%.

Interpretation:

- Invalid proposals remain rejected, but valid proposals cannot finalize when too few validators are available.
- This should be reported as a liveness boundary rather than a robustness failure.

### 4. No lazy validator model

Current state:

- Honest validators recompute checks; Byzantine validators either accept or reject.

Risk:

- A validator may sign without checking.
- Lazy signing weakens the meaning of validator finality.

Improvement:

- Add a "lazy validator" adversary type in future implementation.
- Treat lazy signing of invalid proposals as slashable evidence.

### 5. No slashing or reputation for validators

Current state:

- Validators have signatures but no penalty mechanism.

Risk:

- There is no explicit consequence for signing invalid or conflicting blocks.

Improvement:

- Store validator votes and rejection reasons.
- Add a validator accountability metric:
  - invalid-signing rate;
  - conflicting-signature rate;
  - validator reliability score.

### 6. No Sybil-resistance mechanism

Current state:

- Validator identities are assumed to be permissioned.

Risk:

- If identities are cheap, an attacker can create many validators and exceed threshold.

Improvement:

- Explicitly state permissioned identity management.
- Do not claim permissionless Sybil resistance.

### 7. Aggregator rotation is deterministic

Current state:

- Aggregators are selected by round-robin.

Risk:

- Predictable leaders can be targeted.
- Deterministic ordering is simple but not robust against adaptive denial-of-service or bribery.

Improvement:

- Keep round-robin for reproducibility.
- Mention VRF/randomized selection, stake/reputation-weighted selection, or BFT leader rotation as deployment alternatives.

## Recommended Mechanism Revision

For the next manuscript version, the committee mechanism should be described as:

> a permissioned, threshold-finalized validator committee that independently verifies aggregator authorization, client commitments, decision-rule consistency, hash linkage, and proposal integrity before finalizing an audit block.

Avoid describing it as:

- a complete blockchain consensus protocol;
- a permissionless PoS chain;
- a full PBFT implementation;
- a guarantee against validator-majority collusion.

## Recommended New Experiment

Add a liveness/dropout sensitivity table:

Inputs:

- validator count: 5 or 7;
- threshold: 3 or 5;
- offline validators: 0 to threshold;
- Byzantine validators: 0 or within bound.

Metrics:

- valid block finalization rate;
- finalization failure rate;
- invalid proposal rejection rate;
- mean verification time.

Expected result:

- Safety remains meaningful for invalid proposals when honest validators reject them.
- Liveness fails once too few validators are available to reach threshold.

This is useful because committee protocols are judged on both safety and liveness. Our previous Byzantine-boundary table covers safety; the implemented dropout table covers liveness.

## Manuscript Guidance

In the threat model:

- Define validator set `V`, threshold `q`, and Byzantine validators `b`.
- State that invalid proposals are rejected when fewer than `q` validators sign invalid blocks.
- State that finality can fail when fewer than `q` validators are available.
- State that if `q` Byzantine or lazy validators collude to sign an invalid proposal, the protocol cannot prevent finalization, but the signed votes provide accountability evidence.

In limitations:

- No permissionless identity/Sybil resistance is implemented.
- No full networking consensus, view-change, or mempool ordering is implemented.
- Validator incentives/slashing are modeled as accountability records, not enforced economics.

## Priority for Our Work

High priority:

1. Add liveness/dropout sensitivity. Completed.
2. Add validator accountability metrics.
3. Explicitly frame permissioned committee assumptions.

Medium priority:

1. Add rotating validator subset from a larger pool.
2. Add lazy-validator adversary.

Low priority for current paper:

1. Full PBFT/HotStuff implementation.
2. Real on-chain smart contracts.
3. Permissionless validator admission.
