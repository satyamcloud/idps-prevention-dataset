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

## Quick start (reproducing the dataset from raw data)

1. See `infra/aws/` and `infra/gcp/` for environment setup
2. Run attack scripts per `scripts/attacks/` (or `_gcp` equivalent) to
   collect raw pcap/log data
3. Follow `scripts/phase4_processing/README.md` in order to regenerate
   the final labeled dataset from raw pcaps
4. See `docs/data_dictionary.md` for the final dataset's column reference

## Author

Satyam — PhD Researcher, Amity Institute of Information Technology, Amity University
