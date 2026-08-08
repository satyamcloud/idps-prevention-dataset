# AWS Suricata Configuration Notes

## Environment
- VPC: vpc-09db9194914340c0c (ap-south-1 / Mumbai)
- victim-subnet: subnet-085df829e6e214b10 (10.0.0.0/20)
- attacker-subnet: subnet-062ff7f309350d93a (10.0.16.0/24)
- Route table: rtb-0eec044f52f1cad28 (shared by both subnets)

## VM instances
- Victim: i-0e6cdeb1cd2ad46e0 (t3.small, Ubuntu 26.04 LTS), interface: ens5, private IP 10.0.9.216
- Attacker: i-08f409dac05d62072 (t3.small, Ubuntu 26.04 LTS)

## Security groups
- victim-sg: SSH (My IP only), HTTP (0.0.0.0/0), MySQL 3306 (VPC only),
  ICMP (attacker-subnet), ALL TRAFFIC from attacker-subnet (10.0.16.0/24)
  — this last rule is intentional: AWS SG acts as the outer/internet-facing
  firewall, while Suricata is the internal IDS/IPS boundary. Attacker
  traffic must reach all victim ports for realistic internal-threat simulation.
- attacker-sg: SSH (My IP only), all outbound allowed

## Suricata configuration — IMPORTANT deviation from default
- Default HOME_NET (10.0.0.0/8) swallows BOTH victim-subnet AND
  attacker-subnet, causing EXTERNAL_NET (!$HOME_NET) to never match
  attacker traffic — result: zero alerts despite correct packet capture.
- FIX APPLIED: HOME_NET narrowed to "[10.0.0.0/20]" (victim-subnet only),
  so attacker-subnet (10.0.16.0/24) is correctly treated as EXTERNAL_NET.
- Interface: ens5 (set in af-packet section)
- Rules: default suricata-update pull, 52,197 rules loaded

## Verified working (as of 2026-08-05)
- nmap SYN scan from attacker -> victim correctly triggers alert
  (example: signature_id 2010937, "ET SCAN Suspicious inbound to mySQL port 3306")
- auto_response.py detects alert, blocks source IP via iptables,
  logs action + latency to response_log.json
- Measured action_latency in test: 0.0037 seconds
- Confirmed block is effective: post-block ping from attacker to victim fails

## DVWA (web-attack target)
- Installed on victim VM: Apache + MariaDB + PHP 8.5.4
- DB: dvwa_user / dvwa (config in /var/www/html/config/config.inc.php)
- Security level: Low (attacks succeed unfiltered - needed for realistic
  detection/response testing)
- Verified working: manual SQLi test (1' OR '1'='1) returned all 5 users
- Known non-blocking issues: reCAPTCHA key missing, mod_rewrite not enabled
  (neither needed for our attack categories - SQLi, XSS)
- Login: admin / password (default, fine for isolated testbed)

## Alert throttling (IMPORTANT - affects response_log completeness)
Suricata's ET Open scan-detection rules include built-in per-source-IP
rate limiting: `threshold: type limit, count 5, seconds 60, track by_src`
(confirmed on sig 2010935/2010936/2010937 - MSSQL/Oracle/MySQL scan rules).

This means: repeated identical attacks from the same source within a 60s
window will NOT all generate fresh Suricata alerts after the 5th one -
this is Suricata working as designed, not a pipeline bug.

Implication for dataset: attack_log.json will contain MORE sessions than
response_log.json has corresponding alert-triggered entries. This gap is
expected and should be labeled during Phase 4 as a distinct outcome
category (e.g. "attack_occurred_no_fresh_alert_due_to_threshold") rather
than treated as missing/broken data.
