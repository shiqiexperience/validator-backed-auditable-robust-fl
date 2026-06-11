# Figure and Table Caption List for JISA Submission

## Figures

Figure 1. Clean accuracy and attack success rate on Fashion-MNIST under IID data. Bars report mean clean accuracy over three seeds, error bars report standard deviation, and the line reports ASR.

Figure 2. Clean accuracy and attack success rate on Fashion-MNIST under Dirichlet Non-IID data. FedAvg collapses under sign-flip attacks and shows high ASR under backdoor attacks, while robust aggregation methods maintain competitive clean accuracy and suppress ASR.

Figure 3. Clean accuracy and attack success rate on CIFAR-10 under Dirichlet Non-IID data. Norm filtering achieves the highest clean accuracy in most settings, while the proposed method remains competitive and maintains low ASR with auditable aggregation decisions.

Figure 4. Clean-accuracy comparison between the proposed method and norm filtering across main benchmark conditions.

Figure 5. Attack-success-rate comparison between the proposed method and norm filtering across main benchmark conditions.

Figure 6. Sensitivity to malicious-client ratio on Fashion-MNIST Non-IID adaptive-scaling attacks. All three robust methods remain stable from 10% to 40% malicious clients, with no early stopping.

Figure 7. Audit case round metrics under Fashion-MNIST Non-IID sign-flip attack. The figure shows clean accuracy, ASR, zero-weight rate, and rejection behavior over rounds.

Figure 8. Per-client aggregation weights in the audit case. Malicious clients receive zero aggregation weight across all rounds, while benign clients retain nonzero contribution weights.

## Tables

Table 1. Proposed aggregation hyperparameters.

Table 2. Runtime and audit-log overhead summary.

## Submission Notes

Use separate figure files with logical names such as `Figure_1.pdf`, `Figure_2.pdf`, and so on. Prefer PDF vector files for the current plots where accepted by the submission system. Keep tables as editable text in the manuscript rather than image files.
