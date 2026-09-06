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
