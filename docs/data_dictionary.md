# Dataset Column Reference

## Identifiers
- `id`: NFStream-assigned flow ID (unique within source pcap file only, not globally unique - use row index for global uniqueness)
- `cloud`: "aws" or "gcp" - which cloud environment this flow was captured in
- `session_id`: links to the attack session that generated this flow (null for benign flows)
- `source_pcap_file`: which raw pcap file this flow was extracted from

## Network 5-tuple
- `src_ip`, `dst_ip`: source/destination IP addresses
- `src_port`, `dst_port`: source/destination ports
- `protocol`: IP protocol number (6=TCP, 17=UDP, etc.)
- `ip_version`: 4 or 6

## Flow features (from NFStream)
- `bidirectional_*`: aggregate stats across both directions of the flow
- `src2dst_*`: stats for traffic from source to destination only
- `dst2src_*`: stats for traffic from destination to source only
- `*_first_seen_ms`, `*_last_seen_ms`: Unix timestamps in milliseconds
- `*_duration_ms`: flow duration in milliseconds
- `*_packets`, `*_bytes`: packet and byte counts
- `application_name`, `application_category_name`: NFStream's DPI-based application identification
- `application_confidence`: NFStream's confidence score for the application identification

## Labels (this dataset's core contribution)
- `attack_category`: one of benign, reconnaissance, bruteforce, dos_volumetric,
  dos_slow_l7, web_attack, botnet_beacon
- `intended_severity`: "loud" or "stealthy" - the attack script's intended intensity
  (null for benign)
- `session_notes`: the attack script's own outcome assessment (e.g.
  "loud_scan_timed_out", "stealthy_sqli_blocked_midscan") - useful for
  cross-validation against action_taken
- `action_taken`: the defender's response outcome for this specific flow:
  - `block_ip`: fresh detection, IP blocked for the first time in this session
  - `already_blocked`: repeat alert while the IP was already blocked
  - `blocked_no_new_alert`: the IP was blocked at this flow's timestamp, but
    no NEW alert matched this specific flow (Suricata's per-signature alert
    throttling can suppress repeat alerts even while a block remains active)
  - `false_positive_prevented`: benign victim-side traffic that triggered an
    alert but was correctly NOT blocked (self-protection safeguard)
  - `none`: no detection and no block occurred for this flow
- `action_latency_seconds`: time between Suricata's alert and the response
  script's action, in seconds (null where action_taken is "none")
- `response_signature`: the Suricata rule name that triggered the response
  (null where action_taken is "none")
- `was_blocked_at_flow_time`: boolean, was this source IP under an active
  iptables block at the moment this flow started (independent of whether a
  NEW alert fired for this specific flow)

## Known limitations
- `false_positive_prevented` has very few samples (34 total, all from GCP) -
  useful as a qualitative finding, not a robust classification target
- `dos_volumetric` heavily dominates flow counts (276,278 of 288,738 total)
  due to the nature of SYN-flood traffic generating one flow per packet
- Single-attacker, single-victim testbed (not a simulated multi-host
  organization)
- AWS and GCP environments differ intentionally (Apache vs Nginx, Ubuntu
  version, Suricata rule tuning) - see infra/aws/ and infra/gcp/ config
  notes for full details
