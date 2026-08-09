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
