# IDPS Prevention-Labeled Dataset

A closed-loop intrusion detection + prevention dataset capturing not just
attack/benign classification, but the defender's actual response action,
response latency, and outcome (including false-positive blocks) — across
multiple cloud environments (AWS, GCP).

## Motivation

Existing IDS datasets (CICIDS2017, NSL-KDD, UNSW-NB15) label traffic as
attack/benign only. Closer prior work (Unraveled, 2023) adds a coarse
"Defender Response" label (Benign/Detected/Mitigated) but does not capture
action type, response latency, or false-positive-block outcomes. This
dataset closes that gap.

## Repository structure

- `infra/` — cloud environment setup notes and configs (AWS, GCP)
- `scripts/response/` — auto-response script (Suricata alert -> iptables block -> logged outcome)
- `scripts/attacks/` — attack generation scripts (recon, brute-force, DoS, web, botnet)
- `scripts/benign/` — benign/employee-like traffic generator
- `docs/` — label schema, statistics, config-difference documentation
- `data/raw/` — raw pcap/log data (not committed to git — see .gitignore)

## Status

Work in progress. AWS-side detection + response pipeline verified end-to-end
(Phase 0). GCP replication and full-scale data collection (Phase 3) pending.

## Author

Satyam — PhD Researcher, Amity Institute of Information Technology, Amity University
