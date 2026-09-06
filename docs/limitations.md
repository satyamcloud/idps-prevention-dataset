# Limitations

This section documents known limitations of the dataset and methodology,
identified during construction and validated through direct testing
rather than assumed.

## 1. Testbed scope: single attacker, single victim

The dataset is generated from a controlled testbed with one attacker
host and one victim host per cloud environment, rather than a simulated
multi-host organizational network. This is a deliberate scope choice:
it enables precise, unambiguous ground-truth labeling (attack sessions,
response actions, and outcomes can be attributed without the confounds
of multiple simultaneous actors), at the cost of organizational realism
(no lateral movement, no multiple simultaneous users, no departmental
traffic diversity). Extending to a multi-host environment is identified
as future work.

## 2. Attack category class imbalance

DoS-volumetric traffic accounts for 276,278 of 288,738 total flow
records (95.7%), because SYN-flood traffic generates approximately one
NFStream flow per packet given the attack's structure. Researchers using
this dataset for classification tasks should account for this imbalance
(e.g., via stratified sampling or class weighting) rather than treating
raw flow counts as representative of real-world attack-category
prevalence.

## 3. False-positive-prevented samples are limited

Only 34 flows carry the `false_positive_prevented` label, and all
originate from the GCP environment; the AWS collection run happened to
experience no false-positive-triggering background traffic during its
active window (verified via direct timestamp comparison - see
docs/label_schema.md). This label is included as a genuine, real-world-
observed outcome category and as evidence that the underlying safeguard
mechanism functions correctly, but the sample size is too small to
support robust statistical claims about false-positive rates in
general. Researchers should treat this as a qualitative/descriptive
finding rather than a basis for quantitative false-positive-rate
estimation.

## 4. DoS slow/L7 (Slowloris) is not detected by the deployed ruleset

Across both cloud environments, Slowloris traffic was never detected or
blocked by Suricata's default ruleset. A custom detection rule was
attempted (stream_size-based, matching long-lived low-data connections)
but did not reliably fire, likely because Suricata's stream_size
condition is evaluated on new packet arrival, and Slowloris's defining
behavior (long idle periods between minimal keep-alive sends) rarely
triggers re-evaluation. This is documented as a genuine finding about
signature-based IDS limitations against low-and-slow attacks, not a
data collection failure - the `action_taken: none` label for this
category is accurate and intentional. A connection-state-monitoring
approach (e.g., periodic `ss -tn` polling) could provide detection for
this category in future work.

## 5.
