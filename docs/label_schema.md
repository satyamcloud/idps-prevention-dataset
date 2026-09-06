# Label Schema & Collection Notes

## Reconnaissance category - Phase 1 validation run (2026-08-08)

- 25 attack sessions executed (17 loud `-T4 -p-`, 8 stealthy `-T2 -p 1-150`)
- All 25 sessions successfully logged in attack_log.json (100% capture rate)
- 3 corresponding entries in response_log.json:
  - 1x block_ip (fresh detection + block, latency 0.0095s)
  - 2x already_blocked (repeat alerts, different signature - IMAPS brute-force
    rule triggered by full port scan touching port 993)
- Suricata's built-in alert threshold (count 5, seconds 60, track by_src per
  signature) means dense session batches will show few response_log entries
  relative to attack_log entries - this is EXPECTED, not a pipeline failure.
  See infra/aws/suricata_config_notes.md for full explanation.

## Implication for Phase 4 labeling
When constructing the final action_outcome label, sessions with an attack_log
entry but NO corresponding response_log entry (within a reasonable time
window) should be labeled based on:
1. Check eve.json directly for a matching alert (may exist but throttled by
   response script only reacting to unique alert lines it's watching -
   actually alerts ARE generated & logged by Suricata regardless of threshold
   ONLY when threshold allows; suppressed alerts don't appear in eve.json
   at all)
2. If no alert in eve.json either -> label as "not_detected_due_to_threshold"
   or "not_detected" depending on whether this is the >5th repeat in 60s

## Brute-force category - Phase 1 validation run (2026-08-09)

- 25 attack sessions executed via Hydra against vsftpd (weak test account)
- Custom Suricata rule (sid 9000001) required - default ET ruleset only
  detects FTP brute-force via SERVER response pattern (sid 2002383), not
  attacker request pattern - required self-block protection fix in
  auto_response.py (see suricata_config_notes.md)
- 276 response_log entries: 1x block_ip (fresh), ~263x already_blocked
  (correct recognition across sustained 45+ min run), ~12x
  skipped_self_block_protection (unrelated background APT traffic noise -
  a real example of noise Phase 4 processing must filter)
- No alert threshold suppression observed for custom rule (unlike ET's
  built-in scan rules) - custom threshold clause (count 3, seconds 20,
  track by_src) resets per-window rather than hard-limiting total alerts

## DoS (volumetric) category - Phase 1 validation run (2026-08-09)

- 25 attack sessions executed via hping3 SYN flood against port 80
- Default Suricata signature 2210063 (stream-event:3whs_syn_flood) found
  UNRELIABLE for this purpose - it's a by_flow internal heuristic, not a
  rate-based detector; hping3's per-packet source port randomization
  defeats it. See suricata_config_notes.md for full rate-tuning findings.
- Custom rule (sid 9000002) required: threshold type threshold, track
  by_src, count 100, seconds 5 - reliable and predictable.
- Rate tuning: uncapped --flood (~259k pps) caused 59% kernel packet drops
  and massive alert queue overflow - unusable for clean data. Settled on
  -i u500 (~2000 pps) for "loud" - 0 kernel_drops, clean detection.
- 4023 response_log entries: 1x block_ip (fresh), 4022x already_blocked
  (correct sustained recognition across entire 25-session, ~31min batch)
- 0x self-block issues (this rule only matches external->victim traffic,
  unlike the FTP brute-force response-signature issue)


## DoS (slow/L7) category - Phase 1 validation run (2026-08-09)

- 25 attack sessions executed via Slowloris (50 sockets loud / 25 sockets
  stealthy), against port 80
- ZERO alerts fired during the actual 25-session batch - confirmed
  reproducible non-detection, not a pipeline gap
- Attempted custom detection rule (sid 9000003) using stream_size keyword
  to catch long-lived low-data connections - did NOT fire. Root cause:
  Suricata's stream_size condition is only re-evaluated on new packet
  arrival; Slowloris's defining behavior (long idle periods between
  minimal keep-alive sends) means the condition rarely gets re-checked
  during the actual "slow" phase of the attack.
- DECISION: Documented as legitimate "not_detected" outcome rather than
  engineering a connection-state-monitoring workaround (deferred as
  future enhancement - see Option A note below)
- This is a genuine, citable finding: naive signature-based IDS rules
  are fundamentally limited against low-and-slow attacks; real defenses
  need connection-table/timeout-based monitoring (e.g., Apache
  mod_reqtimeout), not packet-inspection signatures
- FUTURE ENHANCEMENT (not yet built): a script-based connection monitor
  (e.g., periodic `ss -tn` polling) could provide genuine detection for
  this category if revisited later

## IMPORTANT: incidental finding from testing
Default (unreduced) Slowloris socket count (150) DOES trigger the
volumetric DoS rule (sid 9000002) due to the initial connection burst,
even though Slowloris is nominally a "low and slow" attack. Reduced to
50/25 sockets specifically to keep this category's data distinct from
DoS volumetric.

## Web attack category - Phase 1 validation run (2026-08-11)

- 25 attack sessions executed via SQLmap against DVWA SQLi page
  (17 loud --dbs / 8 stealthy --level=1 --risk=1)
- Bug found and fixed: initial script used command.split() which broke
  the --cookie argument (contains a space); fixed with shlex.split()
  and single-quoted f-string. Also added --timeout=5 --retries=1 to
  sqlmap itself so it fails fast on being blocked rather than retrying
  for the full subprocess timeout window.
- Default ET ruleset provides RICH signature diversity for this category
  (unlike bruteforce/DoS which needed custom rules): confirmed firing
  signatures include ET SCAN Sqlmap SQL Injection Scan (sid 2008538),
  ET WEB_SERVER UNION SELECT, XSS script tag, MSSQL xp_cmdshell attempt,
  MySQL information_schema access, /etc/passwd in URI.
- sid 2008538 has built-in threshold (count 2, seconds 40, track by_src) -
  similar to Day-1 scan-rule throttling. Combined with fast blocking
  (~11s/session), most sessions only trigger 1 alert before being cut
  off, so response_log entries are sparse (3 total across 25 sessions)
  despite consistent, correct detection every session (confirmed via
  attack_log outcome notes: all sessions show "blocked_midscan").
- 25/25 attack_log entries, all consistently detected and blocked

## Botnet beacon category - Phase 1 validation run (2026-08-11)

- 25 attack sessions executed via curl-based periodic check-ins
  (17 loud: 8 beacons @ 8s intervals / 8 stealthy: 5 beacons @ 15s intervals)
- SIMPLIFICATION NOTE: real botnet beaconing is victim->C2 (compromised
  host phoning home to attacker infrastructure). Implemented here as
  attacker->victim periodic requests to keep pipeline consistent with
  all other categories (victim-side Suricata detection). This is a
  documented simplification, not full C2 emulation - should be stated
  explicitly as a limitation in the dataset paper.
- Detection finding: signature 2221036 ("SURICATA HTTP Response
  excessive header repetition") fired consistently (184 instances across
  batch) - but same pattern as FTP brute-force: alert's src_ip is the
  VICTIM (server response), not the attacker (beacon requester). Self-
  block protection correctly prevented self-blocking (confirmed 8/8 in
  single-session test, consistent across full batch).
- RESULT: detected via server-side artifact only, NOT actionable against
  the actual attacker IP with current ruleset - similar category to
  DoS slow/L7 (detectable symptom exists, but no clean attacker-directed
  block possible without further custom rule engineering)
- 25/25 attack_log entries logged successfully; no self-inflicted blocks


## FIRST VALID FULL-SCALE RUN (2026-09-04, AWS)

After two invalid attempts (Aug 11 - no pcap; Sep 4 morning - three
pipeline bugs), a fully validated 210-session run completed successfully:

- 35 sessions per category × 6 categories = 210 total
- 7,138 response_log entries
- 0 errors throughout entire run
- Pcap logging enabled (first run with this - full feature extraction
  now viable via NFStream)
- All 3 previously-found bugs fixed and verified:
  - sudo/raw-socket permissions (DoS volumetric)
  - cross-category iptables contamination + flush catch-22
  - Hydra timeout reliability
- Confirmed resilient to operator access disruption (ran correctly
  through an unrelated operator-IP lockout mid-run, since internal
  attacker<->victim communication uses private IPs, independent of
  operator's home IP)

Backed up locally: attack_log.json, response_log.json, eve.json,
pcap files, run_log_real.txt - in data/raw/aws_run_2026-09-04/

THIS IS THE FIRST TRUSTWORTHY, PHASE-4-READY DATASET FROM THIS PROJECT.


## FIRST VALID FULL-SCALE GCP RUN (2026-09-05)

Completed 210-session (35x6) run on GCP, applying all lessons learned
from AWS's earlier bug-fixing session:

- All 3 critical bugs pre-emptively fixed before running (sudo escalation,
  cross-category iptables flush with protected management SSH, timeout-
  wrapped subprocess calls) - NONE recurred during this run
- GCP-specific issues found and fixed: IAP firewall rule requirement,


## Phase 4 label-merging methodology (2026-09-06)

Three-stage labeling pipeline built and validated on both clouds:
1. Session matching: flows matched to attack_log.json sessions by
   src_ip + time window (+/-2s buffer) + target_port if specified
2. Response matching: matched flows checked against response_log.json
   for a corresponding action within +/-5s of flow start
3. Block-state reconstruction: CRITICAL FIX - stage 2 alone mislabels
   flows as "none" (no action) when a category's first session already
   triggered a block that persists (no flush) for the rest of the
   category's sessions - later sessions' flows show "none" simply
   because no NEW alert fired, not because detection/blocking failed.
   Fixed by reconstructing block-state-over-time from block_ip events
   and flush timestamps (found in run_log_real.txt), and relabeling
   "none" -> "blocked_no_new_alert" wherever the IP was actually
   blocked at that flow's timestamp.

Final action_taken categories: block_ip (fresh detection+block),
already_blocked (repeat alert while blocked), blocked_no_new_alert
(IP blocked, but no fresh alert matched this specific flow),
none (genuinely never detected/blocked - e.g. dos_slow_l7, botnet_beacon)

This distinction matters for dataset accuracy: "none" now correctly
means "genuinely undetected", not conflating it with "blocked but
Suricata's per-signature throttling suppressed a fresh alert".

Validated consistent pattern across BOTH clouds independently:
dos_slow_l7 and botnet_beacon show 100% "none" (genuine non-detection),
reconnaissance and web_attack show the blocked_no_new_alert refinement
correctly applied, dos_volumetric/bruteforce dominated by
already_blocked as expected.


## False-positive-prevention labeling (2026-09-06)

Added `false_positive_prevented` outcome label: benign victim-side
traffic that triggered a Suricata alert but was correctly NOT blocked
due to KNOWN_SAFE_IPS self-protection.

RESULT ASYMMETRY (verified, not a bug): GCP run shows 34 such events;
AWS run shows 0. Investigated and confirmed: all of AWS's
skipped_self_block_protection events in response_log.json occurred
during EARLIER testing/debugging (before 16:55), not during the actual
valid collection window (17:02-21:25) - meaning zero false-positive-
triggering background noise happened to occur during AWS's clean run,
while GCP's run did experience such traffic (Go HTTP Client / APT
update checks) during its live collection window.

This is legitimate cross-cloud variation in background traffic
patterns, not a labeling bug - confirmed via direct timestamp
comparison between protection events and flow date ranges.

Final action_taken categories (v3, final):
- block_ip: fresh detection + block
- already_blocked: repeat alert while IP already blocked
- blocked_no_new_alert: IP blocked, no fresh alert matched this flow
- false_positive_prevented: benign flow that WOULD have been blocked
  without self-protection safeguard
- none: genuinely never detected (dos_slow_l7, botnet_beacon primarily)


## FINAL DATASET STATISTICS (2026-09-06)

Total: 288,738 labeled flow records (AWS: 147,852 / GCP: 140,886)

| Category | Cloud | already_blocked | block_ip | blocked_no_new_alert | false_positive_prevented | none |
|---|---|---|---|---|---|---|
| benign | aws | 0 | 0 | 0 | 0 | 1166 |
| benign | gcp | 0 | 0 | 0 | 34 | 80 |
| botnet_beacon | aws | 0 | 0 | 0 | 0 | 247 |
| botnet_beacon | gcp | 0 | 0 | 0 | 0 | 247 |
| bruteforce | aws | 125 | 4 | 0 | 0 | 0 |
| bruteforce | gcp | 125 | 4 | 0 | 0 | 0 |
| dos_slow_l7 | aws | 0 | 0 | 0 | 0 | 1460 |
| dos_slow_l7 | gcp | 0 | 0 | 0 | 0 | 1473 |
| dos_volumetric | aws | 141415 | 147 | 0 | 0 | 0 |
| dos_volumetric | gcp | 134568 | 148 | 0 | 0 | 0 |
| reconnaissance | aws | 0 | 1826 | 1285 | 0 | 0 |
| reconnaissance | gcp | 0 | 2744 | 1285 | 0 | 0 |
| web_attack | aws | 0 | 5 | 172 | 0 | 0 |
| web_attack | gcp | 2 | 4 | 172 | 0 | 0 |

KEY FINDING: strong cross-cloud consistency in detection/response
behavior (bruteforce identical 125/4 split both clouds;
dos_slow_l7/botnet_beacon both 100% "none" both clouds) - suggests
findings reflect genuine signature-based IDS properties, not
environment-specific artifacts.

File: data/processed/final_combined_dataset.csv (not committed to git -
regeneratable via combine_final_dataset.py from raw data in data/raw/)
