# Phase 4: Feature Extraction & Labeling Pipeline

Run these scripts in order to regenerate the final labeled dataset from
raw pcap/log data in `data/raw/`.

## Prerequisites
- NFStream requires Linux (or WSL on Windows - Windows native install
  fails with a DLL error; Npcap does not resolve this, use WSL2 instead)
- `pip install nfstream scikit-learn --break-system-packages`

## Execution order

1. `test_nfstream.py` - sanity check NFStream works on one small pcap
   (optional, for verification only)

2. `process_pcaps.py` - extracts flow features from all pcap files for
   both clouds, outputs `data/processed/{cloud}_flows.csv`

3. `check_pcap_dates.py` - identifies which pcap files belong to the
   valid collection run vs. earlier pilot/test data (adjust date
   ranges inside this script if reprocessing a different run)

4. `filter_aws_flows.py` / `filter_gcp_flows.py` - filters flows to the
   valid run's exact time window (edit start_window/end_window inside
   each script to match your actual run_log_real.txt timestamps),
   outputs `data/processed/{cloud}_flows_filtered.csv`

5. `merge_labels_aws.py` - matches filtered flows to attack_log.json
   sessions by IP + time window, outputs
   `data/processed/aws_flows_labeled_stage1.csv`
   (NOTE: only an AWS version exists; GCP's equivalent logic is
   embedded directly inside fix_labels_gcp.py rather than a separate
   stage1 script - inconsistent, but both produce correct final output)

6. `merge_labels_aws_stage2.py` - adds response_log.json matching
   (action_taken, latency, signature) to AWS's stage1 output

7. `fix_labels_aws.py` / `fix_labels_gcp.py` - CRITICAL step: adds
   block-state reconstruction (relabels "none" -> "blocked_no_new_alert"
   where the IP was actually blocked but no fresh alert fired for that
   specific flow). GCP's script includes stages 1+2+this fix combined
   into one file. Outputs `{cloud}_flows_labeled_final_v2.csv`

8. `add_fp_prevention_label.py` - adds false_positive_prevented label
   by matching skipped_self_block_protection events to benign victim
   flows. Outputs `{cloud}_flows_labeled_final_v3.csv`

9. `combine_final_dataset.py` - merges both clouds into
   `data/processed/final_combined_dataset.csv`, prints statistics table

10. `finalize_dataset_schema.py` - drops diagnostic-only columns
    (MAC addresses, TLS fingerprints, etc.), outputs the final release
    file `data/processed/RELEASE_dataset_v1.csv`

11. `baseline_model_check.py` - Safeguard 5 sanity check, trains a
    RandomForest and reports per-class metrics (see
    docs/label_schema.md for the correct interpretation of results -
    do NOT report overall accuracy alone)

## debug_investigation/

Scripts used during development to investigate specific findings
(e.g., why web_attack showed high "none" rates, verifying the
false-positive asymmetry between clouds). Not part of the core
regeneration pipeline, but preserved for methodological transparency -
see docs/label_schema.md for what each investigation found.

## Known inconsistency to fix in a future cleanup

The AWS and GCP labeling scripts (`merge_labels_aws.py` +
`merge_labels_aws_stage2.py` + `fix_labels_aws.py` vs. the all-in-one
`fix_labels_gcp.py`) grew organically and aren't structured identically.
Both produce correct,


## Validation scripts (added for peer-review response, 2026)

These scripts address reviewer feedback on the baseline classification
methodology and ground-truth labeling validation. Outputs are saved in
`validation_results/`.

- `baseline_model_v2.py` — session-level (not flow-level) train/test
  split using GroupShuffleSplit, confirming zero session leakage.
  Output: `validation_results/session_level_baseline.txt`

- `baseline_model_v3_rigorous.py` — 5-fold session-grouped
  cross-validation (GroupKFold) with explicit hyperparameters, random
  seed, library versions, and a majority-class DummyClassifier
  baseline for comparison. Excludes `false_positive_prevented` from
  the classification target (too few samples - see label_schema.md).
  Output: `validation_results/cv_rigorous_results.txt`

- `cross_cloud_generalization.py` — trains on one cloud's flows,
  tests on the other's, in both directions, to test whether the
  learned model generalizes across environments (not just whether
  label distributions are similar).
  Output: `validation_results/cross_cloud_results.txt`

- `matching_sensitivity_analysis.py` — measures ambiguity in the
  session/response matching windows used during labeling (Section
  3.5/3.6 of the paper): checks for session-boundary overlap and
  counts response events with multiple candidate session matches
  across window sizes +/-1s to +/-10s.
  Output: `validation_results/matching_sensitivity_results.txt`

- `window_distribution_sensitivity.py` — measures whether the
  fraction of sessions with a matched response event changes as the
  matching window size varies (+/-1s to +/-10s), to justify the
  chosen +/-5s window rather than assert it arbitrarily.
  Output: `validation_results/window_sensitivity_results.txt`

- `M5_full_results.txt` — concatenation of the two matching-sensitivity
  outputs above, as sent to paper drafting for the M5 reviewer response.
