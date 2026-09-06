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

## 5. Botnet beacon simulation direction

Real botnet command-and-control beaconing is victim-to-attacker
(a compromised host phoning home). For pipeline consistency with the
other five categories (all of which involve victim-side detection of
attacker-originated traffic), this category is implemented as
attacker-to-victim periodic requests, simulating a C2 server issuing
check-ins to an already-compromised host rather than modeling the
initial compromise or the reverse-direction beacon itself. This is a
deliberate simplification, not a full C2 emulation.

## 6. Detected-but-non-actionable signatures

Two categories (FTP brute-force's response-pattern signature, and
botnet beacon's HTTP-response-repetition signature) are detected by
default Suricata signatures whose `src_ip` field identifies the
VICTIM's response traffic, not the attacker's request traffic. A naive
auto-response system using these signatures directly would self-block
the victim server. This was identified during testing (see
infra/aws/suricata_config_notes.md) and mitigated via an explicit
KNOWN_SAFE_IPS safeguard and, for brute-force, a custom attacker-
directed detection rule. This finding - that not all IDS alerts carry
attacker-side attribution - is documented as a general lesson for
auto-response system design, and readers using this dataset's
`response_signature` field should be aware that signature name alone
does not always indicate attack-source attribution.

## 7. Signature-based IDS alert throttling affects response_log density

Several default Suricata signatures include built-in per-source-IP
alert rate limiting (e.g., `threshold: type limit, count 2, seconds 40,
track by_src` for the SQLmap detection signature; similar patterns on
several ET SCAN rules). Combined with the fact that once an attacker's
IP is blocked it typically remains blocked for the rest of a category's
sessions, this means `response_log.json` contains far fewer entries
than `attack_log.json` sessions for some categories. This is expected,
correct signature behavior, not a data collection gap - it is why the
`blocked_no_new_alert` label exists as distinct from `none` (see
docs/label_schema.md for the full reconstruction methodology).

## 8. Environment differences between AWS and GCP are intentional but not exhaustive

AWS and GCP environments differ by design (Apache vs. Nginx web server,
different Ubuntu versions, independently-tuned Suricata rule sets) to
provide genuine cross-cloud heterogeneity rather than a mirrored
setup. These differences are documented in infra/aws/ and infra/gcp/
config notes. However, the two environments are not intended to be
exhaustive of real-world cloud heterogeneity (e.g., no Azure, no
managed/serverless compute, no container orchestration platforms).

## 9. Baseline model accuracy should not be reported without per-class breakdown

A baseline RandomForest classifier achieves 99.55% overall accuracy on
network-feature-only prediction of `action_taken`, but this figure is
substantially inflated by the trivial separability of the two largest
classes (see docs/label_schema.md for full analysis). Per-class
performance on the more novel labels (`block_ip`, `blocked_no_new_alert`,
`false_positive_prevented`) is meaningfully lower (F1: 0.78-0.87),
indicating genuine but non-trivial learnable signal. Researchers citing
baseline performance on this dataset should report per-class metrics
rather than overall accuracy alone.


## 10. Benign traffic is incidental, not deliberately generated

The original project plan (see repo history / early planning notes)
included a dedicated benign traffic generator to produce realistic,
plentiful "normal user" traffic alongside attack sessions. This was
never implemented; the `benign` label in this dataset instead consists
of incidental background traffic captured during collection (SSH
management connections, OS package-manager checks, DVWA login/browsing
sessions, GCP's internal metadata/guest-agent traffic). As a result,
benign flows are comparatively scarce (1,280 total across both clouds,
versus 276,278 for the dominant dos_volumetric category) and may not
represent the diversity of genuine organizational "normal" traffic
patterns. Researchers requiring a richer benign baseline should
supplement this dataset with dedicated background-traffic generation
(e.g., automated browsing, file transfers, database queries at varied
intervals) - the empty `scripts/benign/` directory in this repository
marks where such a generator was planned but not built, and is left as
a concrete starting point for future extension.
