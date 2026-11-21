# IDPS Prevention-Labeled Dataset

[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.22538006.svg)](https://doi.org/10.5281/zenodo.22538006)

A closed-loop intrusion detection + prevention dataset capturing not just
attack/benign classification, but the defender's actual response action,
response latency, and outcome (including false-positive blocks) — across
two cloud environments (AWS, GCP), six attack categories, and 288,738
labeled network flow records.

## Motivation

Existing IDS datasets (CICIDS2017, NSL-KDD, UNSW-NB15) label traffic as
attack/benign only. Closer prior work (Unraveled, 2023) adds a coarse
"Defender Response" label (Benign/Detected/Mitigated) but does not capture
action type, response latency, or false-positive-block outcomes. This
dataset closes that gap with a fine-grained action taxonomy, latency
measurement, and an explicit false-positive-prevention label, validated
independently across two cloud environments.

## Repository structure

- `infra/aws/`, `infra/gcp/` — cloud environment setup notes, Suricata
  configs, custom detection rules, and troubleshooting logs for each
  cloud environment
- `scripts/attacks/`, `scripts/attacks_gcp/` — attack generation scripts
  (recon, brute-force, DoS-volumetric, DoS-slow/L7, web-attack, botnet-
  beacon) for AWS and GCP respectively
- `scripts/response/` — auto-response script (Suricata alert -> iptables
  block -> logged outcome), with self-block protection
- `scripts/phase4_processing/` — feature extraction (NFStream) and
  label-merging pipeline; see its README.md for exact execution order
- `scripts/benign/` — planned but not implemented (see docs/limitations.md)
- `docs/` — label schema, data dictionary, limitations, statistics,
  and the dataset release README
- `data/raw_logs/` — redacted raw logs of the final AWS and GCP runs
  (attack, response, Suricata alert and run logs), with its own README and
  SHA-256 checksums
- `data/raw/` — full raw pcap/log data (not committed to git — see
  .gitignore). The full Suricata `eve.json` files (redacted) are in Zenodo
  v1.1; the packet captures are not published (names, sizes and SHA-256
  hashes are listed in the Zenodo v1.1 `RAW_LOGS_README.md`)
- `data/processed/` — generated flow CSVs and final labeled dataset
  (not committed — regeneratable via scripts/phase4_processing/)

## Status

**Complete and released**: full 6-category attack infrastructure on both
AWS and GCP; full-scale data collection (210 sessions/cloud
executed on each cloud; see `data/raw_logs/README.md` for known gaps in the
raw logs); feature extraction and label-merging pipeline (Phase 4);
baseline model sanity check; documented limitations. Dataset published
on Zenodo. Latest version (v1.1, adds redacted raw logs):
https://doi.org/10.5281/zenodo.24413511 — v1.0:
https://doi.org/10.5281/zenodo.22538007 — all versions:
https://doi.org/10.5281/zenodo.22538006

## Reproducing the results

There are four levels, from a ten-minute check to a full re-collection.
Levels 1 and 2 can be run by anyone with the files in this repository.

All commands are run from the repository root. Python 3.10 or later with
`pandas`, `numpy` and `scikit-learn` is enough for Levels 1 and 2
(`pip install pandas numpy scikit-learn`).

**Library version.** The fold assignment of `GroupKFold` depends on the
scikit-learn version. The numbers in the paper were produced with
scikit-learn 1.9.x. With 1.7.2 the same script gives the same accuracy
(99.62% against 99.61%), but eight `block_ip` flows fall in a different
fold and the RandomForest macro-F1 is 94.0% instead of 95.0%. Use 1.9.x to
reproduce the paper's numbers exactly.

### Level 1: check the classification results from the released CSV

Input: `release_package/RELEASE_dataset_v1.csv` (288,738 flows; 147,852 AWS
and 140,886 GCP).

```
python scripts/phase4_processing/baseline_model_v3_rigorous.py
python scripts/phase4_processing/cross_cloud_generalization.py
python scripts/phase4_processing/baseline_model_v2.py
python scripts/phase4_processing/reviewer_analyses.py \
    release_package/RELEASE_dataset_v1.csv check.json
```

The scripts print their results; reference outputs are in
`scripts/phase4_processing/validation_results/`. Headline values to compare
(5-fold session-grouped cross-validation, RandomForest with 100 trees,
seed 42, 12 flow features): accuracy 99.61% (std 0.46) against a 96.10%
majority-class baseline; with `reviewer_analyses.py`, macro-F1 95.0% and
balanced accuracy 94.2% (see Tables 12 and 13 of the paper and
`validation_results/reviewer_analyses_results.json`).

### Level 2: check the response-matching analysis from the released raw logs

Input: the redacted raw logs in `data/raw_logs/` (see its README for the
final-run windows and for known gaps in the logs). The analysis scripts
read from `data/raw/`, so copy the two run folders there first:

```
mkdir -p data/raw
cp -r data/raw_logs/aws_run_2026-09-04 data/raw/
cp -r data/raw_logs/gcp_run_2026-09-05 data/raw/
python scripts/phase4_processing/matching_sensitivity_analysis.py
python scripts/phase4_processing/window_distribution_sensitivity.py
```

Expected: no session boundary overlaps (0 of 210 sessions on each cloud);
no response event with more than one candidate session at any window from
+/-1 s to +/-10 s (0 of 7,138 AWS and 0 of 6,874 GCP response records; these
counts are whole-file counts, which also include earlier test activity);
sessions with a matched response event: 49 of 210 at +/-1 s and 60 of 210
at +/-3 s, +/-5 s and +/-10 s, on both clouds.

(`data/raw/` is not tracked by git, see `.gitignore`.)

### Level 3: regenerate the flows and labels from the packet captures

This needs the original pcap files, which are not published because their
payloads contain unredacted addresses. Their names, sizes and SHA-256
hashes are listed in `RAW_LOGS_README.md` of Zenodo version 1.1, and they
can be requested from the corresponding author. Place them, together with
the raw logs, in `data/raw/aws_run_2026-09-04/` and
`data/raw/gcp_run_2026-09-05/`, then follow
`scripts/phase4_processing/README.md` in the order given there. NFStream
needs Linux (or WSL2 on Windows). The two filter scripts contain the
start and end of each run's valid collection window, which must match the
run (see `data/raw_logs/README.md`). The last step writes the final file
`data/processed/RELEASE_dataset_v1.csv`; compare it with
`release_package/RELEASE_dataset_v1.csv`.

### Level 4: re-collect new data

1. Set up the two environments as described in `infra/aws/` and
   `infra/gcp/` (Suricata with the custom rules in `local.rules`, a
   vulnerable web target (DVWA), an FTP service for the brute-force
   category, and an attacker host in the same network).
2. Start the response script (`scripts/response/auto_response.py`, with the
   GCP variant in `scripts/attacks_gcp/auto_response.py`) on the victim.
3. Run `run_all_categories.py` from `scripts/attacks/` (AWS) or
   `scripts/attacks_gcp/` (GCP) on the attacker host with `sudo`; it flushes
   the victim's firewall between categories and runs 35 sessions per
   category.
4. Copy the attack, response and Suricata logs and the packet captures to
   `data/raw/` and continue with Level 3.

The collection scripts contain constants specific to the original
environments (victim and attacker addresses, `KNOWN_SAFE_IPS` in the
response script, user names and key paths) that must be edited before use.
The AWS copy of the slow/L7 DoS script (`dos_slowloris_attack.py`) is
referenced by `scripts/attacks/run_all_categories.py` but is not in this
repository; the GCP version in `scripts/attacks_gcp/` can be adapted by
changing the target address.

## Author

Satyam — PhD Researcher, Amity Institute of Information Technology, Amity University
