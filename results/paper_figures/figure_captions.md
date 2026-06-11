# Figure Captions and Usage Notes

## `fashionmnist_iid_main`

Suggested caption: Clean accuracy and attack success rate on Fashion-MNIST under IID data. Bars report mean clean accuracy over three seeds, error bars report standard deviation, and the line reports ASR. The proposed method remains competitive with norm filtering across sign-flip, adaptive-scaling, and backdoor attacks.

Usage note: Use this figure to support the claim that the proposed method is stable under IID data, not to claim a large accuracy advantage.

## `fashionmnist_noniid_main`

Suggested caption: Clean accuracy and attack success rate on Fashion-MNIST under Dirichlet Non-IID data. FedAvg collapses under sign-flip attacks and shows high ASR under backdoor attacks, while robust aggregation methods preserve clean accuracy and suppress ASR.

Usage note: This is the most useful Fashion-MNIST main figure because it shows the heterogeneous-data setting.

## `cifar10_noniid_main`

Suggested caption: Clean accuracy and attack success rate on CIFAR-10 under Dirichlet Non-IID data. Norm filtering achieves the highest clean accuracy in most settings, while the proposed method remains competitive and maintains low ASR with auditable aggregation decisions.

Usage note: This figure is important for honest positioning. It shows that the proposed method is not uniformly accuracy-best on CIFAR-10.

## `proposed_vs_norm_filter_accuracy`

Suggested caption: Clean-accuracy comparison between the proposed method and norm filtering across main benchmark conditions.

Usage note: Use together with the ASR comparison to discuss the accuracy-security tradeoff.

## `proposed_vs_norm_filter_asr`

Suggested caption: Attack-success-rate comparison between the proposed method and norm filtering across main benchmark conditions.

Usage note: This figure helps support the low-ASR claim, especially where clean accuracy is close.

## `malicious_ratio_sensitivity`

Suggested caption: Sensitivity to malicious-client ratio on Fashion-MNIST Non-IID adaptive-scaling attacks. All three robust methods remain stable from 10% to 40% malicious clients, with no early stopping.

Usage note: This figure supports robustness stability under increased malicious participation. It does not support a universal superiority claim for the proposed method.
