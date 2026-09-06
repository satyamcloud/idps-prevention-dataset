# Related Work Comparison

## Comparison table: this dataset vs. closest prior work

| Feature | This dataset | Unraveled (2023) | GenTI (2026) | SIR-Bench (2026) |
|---|---|---|---|---|
| Action-type granularity | Fine-grained (block_ip, already_blocked, blocked_no_new_alert, false_positive_prevented, none) | Coarse (Benign/Detected/Mitigated only) | N/A - motivational gap, no dataset released | Agent-investigation TP/FP counts, not flow-level actions |
| Response latency captured | Yes (action_latency_seconds, per-flow) | No | N/A | No |
| False-positive-outcome labeled | Yes (explicit false_positive_prevented label, quantified) | No | N/A | Partial (TP/FP at incident level, not action-outcome level) |
| Multi-cloud | Yes (AWS + GCP, independently validated) | No (single environment) | N/A | N/A |
| Granularity level | Network flow | Network flow + host logs | N/A | Security incident (SOC-analyst level) |
| Attack categories | 6 (recon, bruteforce, DoS-volumetric, DoS-slow/L7, web-attack, botnet-beacon) | APT-focused, multi-stage | N/A | Brute force, unauthorized access, misconfiguration, malicious file execution |
| Real pcap-derived features | Yes (NFStream, 288,738 flows) | Yes (NetFlow-style) | N/A | No (incident metadata only) |

## Differentiation narrative

**vs. Unraveled**: Unraveled's "Defender Response" label is a single
categorical field (Benign/Detected/Mitigated) designed to explain
attacker behavioral adaptation in an APT scenario, not to characterize
the defender's action itself. It does not specify which mitigation
mechanism was used, how quickly it was applied, or whether it succeeded
without side effects. This dataset's action_taken field distinguishes
five outcomes including a genuine false-positive-prevention category,
directly measures response latency, and additionally provides
cross-cloud validation absent from Unraveled's single-environment
design.

**vs. GenTI**: GenTI identifies the same motivating gap this dataset
addresses (existing datasets lack structure to support automated
prevention-rule synthesis) but is a methods/framework paper, not a
released labeled dataset — this dataset provides the empirical artifact
GenTI's argument calls for.

**vs. SIR-Bench**: SIR-Bench operates at the security-incident level,
evaluating whether an LLM-based SOC agent correctly investigates and
classifies incidents as true/false positive. This dataset operates at
the network-flow level, characterizing the automated IDPS's own
real-time detect-and-respond behavior rather than a downstream analyst
or agent's investigation quality. The two are complementary rather than
overlapping: SIR-Bench could plausibly consume a dataset like this one
as raw incident material for agent evaluation.

## Note on literature currency

This comparison reflects a literature check conducted in [MONTH/YEAR OF
YOUR LITERATURE REVIEW - fill in]. Given the pace of related work in
this space (multiple relevant papers identified within the preceding
few months of that check), a final literature verification immediately
before submission is recommended (see project notes on this practice).
