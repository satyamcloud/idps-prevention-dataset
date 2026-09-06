# IDPS Prevention-Labeled Dataset

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
- `data/raw/` — raw pcap/log data (not committed to git — see .gitignore)
- `data/processed/` — generated flow CSVs and final labeled dataset
  (not committed — regeneratable via scripts/phase4_processing/)

## Status

**Complete**: full 6-category attack infrastructure on both AWS and GCP;
validated full-scale data collection (210 sessions/cloud, 0 errors);
feature extraction and label-merging pipeline (Phase 4); baseline model
sanity check; documented limitations.

**Pending**: dataset upload to Zenodo/IEEE DataPort with DOI; university
IPR/licensing confirmation; paper writing.

## Quick start (reproducing the dataset from raw data)

1. See `infra/aws/` and `infra/gcp/` for environment setup
2. Run attack scripts per `scripts/attacks/` (or `_gcp` equivalent) to
   collect raw pcap/log data
3. Follow `scripts/phase4_processing/README.md` in order to regenerate
   the final labeled dataset from raw pcaps
4. See `docs/data_dictionary.md` for the final dataset's column reference

## Author

Satyam — PhD Researcher, Amity Institute of Information Technology, Amity University
