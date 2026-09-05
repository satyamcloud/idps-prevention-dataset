#!/usr/bin/env python3
"""
Reconnaissance attack script - GCP version.
"""
import subprocess
import time
import sys
from attack_logger import log_attack_session, now_utc

TARGET_IP = "10.1.0.2"
SOURCE_IP = "10.1.1.2"
CLOUD = "gcp"
MAX_SCAN_SECONDS = 120

def run_scan(session_num, scan_type, nmap_args, severity):
    session_id = f"recon_{CLOUD}_{session_num:03d}"
    command = f"nmap {nmap_args} {TARGET_IP}"

    start_ts = now_utc()
    print(f"[{session_id}] Starting: {command}")

    outcome_note = scan_type
    try:
        result = subprocess.run(
            command.split(),
            capture_output=True,
            text=True,
            timeout=MAX_SCAN_SECONDS
        )
    except subprocess.TimeoutExpired:
        print(f"[{session_id}] TIMED OUT after {MAX_SCAN_SECONDS}s")
        outcome_note = f"{scan_type}_timed_out"
    except Exception as e:
        print(f"[{session_id}] ERROR: {e}")
        outcome_note = f"{scan_type}_error"
    finally:
        end_ts = now_utc()
        log_attack_session(
            session_id=session_id,
            attack_category="reconnaissance",
            tool="nmap",
            command=command,
            start_ts=start_ts,
            end_ts=end_ts,
            source_ip=SOURCE_IP,
            target_ip=TARGET_IP,
            cloud=CLOUD,
            target_port=None,
            intended_severity=severity,
            notes=outcome_note
        )
        print(f"[{session_id}] Logged. Duration: {(end_ts - start_ts).total_seconds():.2f}s")

if __name__ == "__main__":
    num_sessions = int(sys.argv[1]) if len(sys.argv) > 1 else 5

    for i in range(1, num_sessions + 1):
        if i % 3 == 0:
            run_scan(i, "stealthy_scan", "-sS -T2 -p 1-150", "stealthy")
        else:
            run_scan(i, "loud_scan", "-sS -T4 -p-", "loud")
        time.sleep(65)
