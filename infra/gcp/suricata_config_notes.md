---
name: gcp-suricata-config-notes
description: GCP Phase 0 setup notes - VPC, firewall, Suricata config, and OS Login sudo instability findings
---

# GCP Setup Notes

## Environment
- VPC: idps-dataset-vpc (asia-south1 / Mumbai)
- victim-subnet: 10.1.0.0/24
- attacker-subnet: 10.1.1.0/24
- Victim VM: victim-web-1 (e2-medium, Ubuntu 26.04 LTS Minimal), private IP 10.1.0.2, interface ens4
- Attacker VM: attacker-1 (e2-medium, Ubuntu 26.04 LTS Minimal), private IP 10.1.1.2

## Firewall rules (GCP's equivalent of AWS security groups - VPC-wide, tag-based)
- allow-ssh-victim: tag victim, source <operator IP>/32, tcp:22
- allow-http-victim: tag victim, source <operator IP>/32, tcp:80
- allow-attacker-to-victim: tag victim, source 10.1.1.0/24, all protocols
- allow-ssh-attacker: tag attacker, source <operator IP>/32, tcp:22
- allow-iap-ssh: tags victim+attacker, source 35.235.240.0/20, tcp:22
  CRITICAL: GCP's browser-based SSH (Cloud IAP) connects from this
  specific Google-owned IP range, NOT the operator's IP. Without this
  rule, browser SSH fails with "Connection via Cloud Identity-Aware
  Proxy Failed... Code: 4003". This is a GCP-specific requirement with
  no AWS equivalent.

## CRITICAL: OS Login sudo instability (2026-09-05)
GCP's OS Login grants sudo dynamically via IAM role "Compute OS Admin
Login", refreshed periodically by a systemd timer
(google-oslogin-cache.timer, ~5.5hr interval observed). This refresh
appears to intermittently and unpredictably DROP sudo access mid-session
(observed multiple times within ~1 hour), with sudo returning
"I'm afraid I can't do that" / "may not run sudo" errors despite correct
IAM role assignment (confirmed: Owner + Compute OS Admin Login both
present, no conflicting duplicate roles).

Workarounds tried:
- Reconnecting SSH session: worked sometimes, not reliably
- Full VM restart: worked once, but issue recurred later same session

PERMANENT FIX APPLIED: added user to the LOCAL Linux `sudo` group
directly (bypassing OS Login's dynamic IAM-based grant entirely) via a
VM startup script:
  GCP Console -> VM -> Edit -> Automation -> Startup script:
    #!/bin/bash
    usermod -aG sudo <username>
  (requires Stop+Start, not just reconnect, to execute)
This adds a STATIC (ALL:ALL) ALL sudoers entry that does not depend on
IAM sync. However, this entry requires a PASSWORD (unlike OS Login's
NOPASSWD entry) - so ALSO set a password via a second startup script:
    echo "<username>:<password>" | chpasswd
Use `sudo -n <command>` to test whether the passwordless (OS Login)
path is currently active; falls back needs the password from chpasswd
if OS Login's grant has dropped.

LESSON: for any future GCP VM in this project, apply BOTH startup
scripts (usermod + chpasswd) at VM CREATION time, not reactively after
hitting this issue - would have saved significant debugging time.

## Suricata config
- af-packet interface: ens4 (NOT eth4 - a default/stale value was found
  in a fresh suricata.yaml despite no obvious source; always verify via
  `ip a` and explicitly set, don't trust any pre-filled default)
- HOME_NET: [10.1.0.0/24] (narrowed from default, same lesson as AWS Day 1)
- pcap-log: enabled from the start this time (enabled: yes, limit: 500mb,
  max-files: 10, ~5GB cap - more generous than AWS's 1.5GB, since GCP's
  disk had 17GB available vs AWS's 2.9GB)
- `nano` and `ping` (iputils-ping) not pre-installed on Ubuntu Minimal
  image - install as needed, same pattern as AWS's occasional missing
  packages


## DVWA + Nginx setup (2026-09-05)
- Nginx + PHP-FPM 8.5 + MariaDB (variation from AWS's Apache stack)
- PHP-FPM socket: /run/php/php8.5-fpm.sock
- Nginx site config: standard PHP-FPM passthrough via fastcgi_pass
- DB: dvwa_user / dvwa_pass123 / dvwa database (same credentials as AWS
  for consistency)
- allow_url_include enabled in /etc/php/8.5/fpm/php.ini
- Security level resets to "Impossible" on fresh DB creation - same as
  AWS, must be manually set to Low each time DB is recreated
- Verified working: manual SQLi test (1' OR '1'='1) returned all 5 users
