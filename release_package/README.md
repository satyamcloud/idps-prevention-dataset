# IDPS Prevention-Labeled Dataset — v1

A closed-loop intrusion detection and prevention dataset capturing not
just attack/benign classification, but the defender's actual response
action, response latency, and outcome — including false-positive
blocks — across two cloud environments (AWS, GCP).

## Motivation

Existing IDS datasets (CICIDS2017, NSL-KDD, UNSW-NB15) label traffic as
attack/benign only. The closest prior work (Unraveled, 2023) adds a
coarse "Defender Response" label (Benign/Detected/Mitigated) but does
not capture action type, response latency, or false-positive-block
outcomes. This dataset closes that gap with a fine-grained action
taxonomy, latency measurement, and an explicit false-positive-outcome
label, validated across two independent cloud environments.

## Contents

- `RELEASE_dataset_v1.csv`: 288,738 labeled network flow records
- `data_dictionary.md`: full column reference
- `limitations.md`: documented scope and known limitations
- `label_schema.md`: full methodology for label construction, including
  the block-state reconstruction fix and false-positive-prevention
  labeling logic

## Attack categories

reconnaissance, bruteforce, dos_volumetric, dos_slow_l7, web_attack,
botnet_beacon (see data_dictionary.md for full label definitions)

## Generation

Full generation code (attack scripts, detection/response system,
feature extraction pipeline) is available at:
https://github.com/satyamcloud/idps-prevention-dataset

## Citation

[To be added upon publication]

## License

This dataset is released under the **Creative Commons Attribution 4.0
International License (CC-BY 4.0)**. You are free to share and adapt
this dataset for any purpose, including commercially, provided
appropriate credit is given (see Citation section).

Full license text: https://creativecommons.org/licenses/by/4.0/

## Copyright

© 2026 Satyam Shivam Sunderam, Dr. Sunil Kumar Khatri, Dr. Ankur Garg
