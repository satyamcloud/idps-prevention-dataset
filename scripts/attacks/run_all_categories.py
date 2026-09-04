#!/usr/bin/env python3
"""
Master script - runs all 6 attack categories sequentially.
Flushes iptables on the victim VM between each category, and always
re-adds a protective ACCEPT rule for the attacker's own management SSH
connection FIRST - otherwise once the victim blocks the attacker's IP,
the attacker can no longer reach the victim at all to clear the block
(a self-defeating catch-22 discovered during testing).
"""
import subprocess
import time
import datetime

SESSIONS_PER_CATEGORY = 3
GAP_BETWEEN_CATEGORIES = 60  # seconds
VICTIM_IP = "10.0.9.216"
ATTACKER_IP = "10.0.16.175"
VICTIM_SSH_KEY = "/home/ubuntu/victim_access_key"

SCRIPTS = [
    "recon_attack.py",
    "bruteforce_attack.py",
    "dos_volumetric_attack.py",
    "dos_slowloris_attack.py",
    "web_attack.py",
    "botnet_beacon_attack.py",
]

def log(msg):
    print(f"[{datetime.datetime.now().isoformat()}] {msg}", flush=True)

def flush_victim_iptables():
    cmd = [
        "ssh", "-i", VICTIM_SSH_KEY, "-o", "StrictHostKeyChecking=no",
        f"ubuntu@{VICTIM_IP}",
        f"sudo iptables -F INPUT && sudo iptables -I INPUT 1 -p tcp -s {ATTACKER_IP} --dport 22 -j ACCEPT"
    ]
    try:
        subprocess.run(cmd, timeout=15, check=True, capture_output=True, text=True)
        log("Victim iptables flushed + management SSH rule re-added.")
    except Exception as e:
        log(f"!!! FAILED to flush victim iptables: {e} - manual intervention needed!")

for script in SCRIPTS:
    log(f"=== Flushing iptables before {script} ===")
    flush_victim_iptables()

    log(f"=== Starting {script} with {SESSIONS_PER_CATEGORY} sessions ===")
    try:
        subprocess.run(["sudo", "python3", script, str(SESSIONS_PER_CATEGORY)], check=True)
    except subprocess.CalledProcessError as e:
        log(f"!!! {script} exited with error: {e} - continuing to next category")
    except Exception as e:
        log(f"!!! Unexpected error in {script}: {e} - continuing to next category")
    log(f"=== Finished {script}. Sleeping {GAP_BETWEEN_CATEGORIES}s before next category ===")
    time.sleep(GAP_BETWEEN_CATEGORIES)

log("=== ALL CATEGORIES COMPLETE ===")
