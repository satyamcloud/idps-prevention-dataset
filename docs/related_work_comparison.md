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

This comparison reflects a literature check conducted in September 2026. Given the pace of related work in
this space (multiple relevant papers identified within the preceding
few months of that check), a final literature verification immediately
before submission is recommended (see project notes on this practice).


## Additional comparison: Dash & Acken (2026) — latency framework

| Feature | This dataset | Dash & Acken (2026) |
|---|---|---|
| Contribution type | Empirical dataset | Formal latency framework + demonstration |
| Latency scope | Response/action latency (alert -> block action) | Full end-to-end decomposition (ACL + IDL + PDL), including detection-pipeline sub-stages (data collection, buffering, processing, feature extraction, inference) |
| Applied to a released, response-labeled dataset | Yes (288,738 flows, real action_latency_seconds from real block events) | No - applies framework to ROSPaCe (CPS/IoT dataset), which lacks response-action instrumentation; only inference-time (a single IDL sub-component) is computable |
| Domain | Cloud-hosted network services (AWS, GCP) | IoT/CPS/edge/federated deployments |

**Differentiation narrative**: Dash & Acken (2026, Cybersecurity) make a
formal, valuable case that latency is an underexplored IDS metric and
that existing datasets - even recent ones like ROSPaCe - are
"latency-partial," lacking the response-action instrumentation needed
to compute their full PDL (Post-Detection Latency, which includes
alert-generation and response-time components closely analogous to
this dataset's action_latency_seconds field). Their own demonstration
on ROSPaCe could only compute inference time, not the full latency
decomposition, precisely because ROSPaCe - like most IDS datasets -
was not built with a live auto-response mechanism generating real
action timestamps. This dataset directly supplies what their analysis
identifies as missing: real, empirically-measured response latency
from an actual closed-loop detect-and-block system, across thousands
of genuine alert-to-action events on two independent cloud
environments. This is complementary evidence FOR this dataset's value,
not a competing artifact - a future revision of this dataset could
adopt Dash & Acken's formal ACL/IDL/PDL decomposition as the reporting
standard for the latency field already captured here.

## Literature currency note (updated)

A second literature check was conducted in September 2026 (see project
notes), covering searches for: intrusion prevention datasets with
action/latency labeling (2026), closed-loop IDPS datasets with
false-positive-outcome labeling, and IDS latency frameworks. No dataset
combining fine-grained action-type taxonomy + response latency +
false-positive-outcome labeling + multi-cloud validation was found,
confirming the novelty claim remains intact as of this date. One
highly relevant complementary paper was identified (Dash & Acken 2026,
above) and incorporated. A final check immediately before submission
is still recommended given the pace of this literature.
