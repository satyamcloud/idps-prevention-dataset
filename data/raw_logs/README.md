# Raw logs of the final collection runs

Logs behind the released dataset, with the redactions listed below.
All timestamps are UTC.

| Run | Final-run window (UTC) | Directory |
|---|---|---|
| AWS | 2026-09-04 17:02:31 to 21:24:01 | `aws_run_2026-09-04/` |
| GCP | 2026-09-05 11:53:28 to 16:47:07 | `gcp_run_2026-09-05/` |

## Files (per run)
- `attack_log.json`: ground truth, one JSON line per attack session (210 per cloud).
- `response_log.json`: one JSON line per response action of `auto_response.py`.
- `eve_alerts.json`: Suricata `eve.json` lines with `event_type` = `alert` only (the full `eve.json` is not included).
- `run_log_real.txt`: output of the attack driver script.

## Read this before using the files
- **The response and alert logs also contain earlier test activity**, not only the final run. AWS response log: 7,138 records, of which 5,938 fall inside the final-run window (1,200 before it). GCP response log: 6,874 records, of which 5,975 fall inside the window (888 before and 11 after). Filter by the window above.
- **AWS response records are missing at the end of the run.** From 20:32:20 UTC to the end of the AWS run, Suricata raised 362 alerts whose source is the victim host (247 "HTTP Response excessive header repetition", 115 "GNU/Linux APT User-Agent Outbound"). The AWS response log has no record for any of them. The cause has not been established. The corresponding victim-originated alerts on GCP were logged as `skipped_self_block_protection`.
- The failed pilot run of 2026-08-11 is not part of the dataset and is not included.

## Redactions
Applied to copies; originals were not modified.
- The operator's public IPv4 addresses are replaced by `198.51.100.1` to `198.51.100.3`.
- The victim VMs' public IPv4 addresses are replaced by `198.51.100.10` (GCP) and `198.51.100.11` (AWS).
- One further public address that contacted the AWS victim before the final run is replaced by `198.51.100.12`.
- The DVWA session cookie value is replaced by `REDACTED`.
- The Linux username on the GCP machines is replaced by `user`.
- Private addresses and third-party service addresses are unchanged.

`SHA256SUMS.txt` lists the SHA-256 hash of every file in this folder.
