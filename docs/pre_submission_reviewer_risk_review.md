# Pre-Submission Reviewer Risk Review

Date: 2026-06-14

## Scope

This review checks whether the revised manuscript still contains desk-reject risks after the shift from centralized hash-chain logging to permissioned validator-backed audit finality.

## Overall Assessment

The revised manuscript is substantially stronger than the rejected version because it no longer relies on a single aggregation server to both compute weights and finalize the audit log. The new framing makes the robust aggregation decision itself a validator-verifiable object.

The manuscript is not yet ready for submission, but the remaining issues are now mostly positioning and evidence-boundary issues rather than the previous fatal security-model flaw.

## P0 Blocking Issues

No current P0 blocker was found in this pass.

The previous P0 issue was:

- the same central server computed scores, determined weights, and wrote the hash chain.

Current status:

- resolved at the manuscript level by introducing rotating aggregator proposals, client commitments, validator verification, threshold finality, Byzantine-boundary experiments, and liveness/dropout experiments.

## P1 Major Risks

### 1. "Decentralized" may still be challenged

Risk:

- The title uses "Decentralized", while the implementation is a permissioned threshold-finality simulation rather than a full P2P blockchain with networking consensus.

Current mitigation:

- The abstract, threat model, method, and limitations now state permissioned validators, threshold finality, and no full PBFT/HotStuff/Tendermint implementation.

Remaining decision:

- Keep current title if targeting a venue that accepts system-model papers with simulations.
- Consider a more conservative title before submission:

> Permissioned Validator-Backed Auditable Robust Aggregation for Federated Learning Against Poisoning and Aggregator Tampering

or

> Validator-Backed Auditable Robust Aggregation for Federated Learning Against Poisoning and Aggregator Tampering

### 2. Validator finality experiments are protocol simulations

Risk:

- Reviewers may ask why there is no real consensus network, no smart contract, no validator selection, and no message-delay/liveness protocol.

Current mitigation:

- The manuscript explicitly states that it is not a full blockchain deployment.
- Results include safety and liveness boundaries.

Remaining improvement:

- Add one concise paragraph in the experimental setup explaining why protocol simulation is used: it isolates application-level validity predicates before implementing expensive networking consensus.

### 3. Missing empirical FLTrust/FLAME baselines

Risk:

- Security reviewers may expect FLTrust and FLAME because they are strong and well-known FL defenses.

Current mitigation:

- The manuscript explicitly states that FLTrust and FLAME are related-work references, not empirical baselines, and explains why.

Remaining improvement:

- If time allows, implement one of them or add a stronger justification table comparing trust assumptions:
  - FLTrust requires trusted root data.
  - FLAME is backdoor-specific.
  - Proposed focuses on auditable aggregation finality.

### 4. Current validator committee lacks incentives and slashing

Risk:

- Committee-based blockchain reviewers may ask what prevents lazy validators or validators signing invalid proposals.

Current mitigation:

- Manuscript states that threshold collusion breaks finality and that signatures provide accountability evidence.
- Limitations state no slashing, no validator reputation, no permissionless Sybil resistance.

Remaining improvement:

- Add a lightweight validator-accountability metric or a future-work paragraph:
  - invalid-signing rate;
  - conflicting-signature rate;
  - validator reliability score.

## P2 Moderate Risks

### 1. Clean accuracy is not consistently best

Risk:

- Reviewers may ask why the method is valuable if norm filtering is stronger on CIFAR-10.

Current mitigation:

- Manuscript already states the method is not universally clean-accuracy superior.
- Contribution is positioned as competitive robust accuracy plus validator-backed auditability.

Remaining improvement:

- In the abstract or conclusion, keep "competitive" rather than "better".

### 2. DFL-specific poisoning is not fully evaluated

Risk:

- Recent DFL work studies collusive attacks and decentralized propagation attacks that differ from centralized poisoning.

Current mitigation:

- Current attacks cover sign-flip, adaptive-scaling, and backdoor.
- Aggregator-side tampering is evaluated separately.

Remaining improvement:

- Add DFL-specific collusive poisoning only if implementation effort is reasonable.
- Otherwise keep it as future work.

### 3. Reference quality varies

Risk:

- Several recent committee/DFL references are arXiv preprints.

Current mitigation:

- The paper also cites established peer-reviewed robust FL and blockchain-FL works.

Remaining improvement:

- Before submission, re-check whether 2024-2026 preprints have journal/conference versions.
- Do not over-rely on preprints for core claims.

## Changes Made During This Review

- Removed duplicated old abstract text.
- Replaced old single-server method residue with selected-aggregator wording.
- Tightened strong claims:
  - from "prevents catastrophic poisoning failures";
  - to "avoids the catastrophic poisoning failures observed for unprotected FedAvg".
- Clarified conventional server-mediated FL in the introduction.
- Reframed the proposed system as permissioned validator-backed audit finality.
- Clarified that audit records are finalized only after validator verification and threshold signing.

## Current Recommendation

Proceed to the next revision stage, but do not submit yet.

Recommended next step:

1. Add a short validator-protocol simulation rationale in Experimental Setup.
2. Add a compact trust-assumption comparison table or paragraph.
3. Decide whether to keep "Decentralized" in the title or change it to "Permissioned Validator-Backed" before submission.

