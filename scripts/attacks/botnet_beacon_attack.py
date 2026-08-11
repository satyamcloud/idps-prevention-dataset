#!/usr/bin/env python3
"""
Botnet beacon attack script - Phase 1, Category 6 (final).
Simulates periodic C2 check-in traffic: small HTTP requests at regular
intervals, mimicking a malware beacon pattern.
NOTE: Real botnet beaconing is victim->C2 (compromised host phoning home).
Simplified here as attacker->victim periodic small requests to keep the
pipeline consistent with all other categories (victim-side detection).
This is a documented simplification, not a full C2 emulation.
"""
import subprocess
import time
import sys
from attack_logger import log_attack_session, now_utc

TARGET_IP = "10.0.9.216"
SOURCE_IP = "10.0.16.175"
CLOUD = "aws"
MAX_ATTACK_SECONDS = 120

def run_beacon(session_num, attack_type, beacon_count, interval, severity):
    session_id = f"botnet_beacon_{CLOUD}_{session_num:03d}"
    command = f"curl -s -H X-Beacon-ID:{session_id} http://{TARGET_IP}/"

    start_ts = now_utc()
    print(f"[{session_id}] Starting beacon campaign: {beacon_count} check-ins, {interval}s apart")

    outcome_note = attack_type
    try:
        for i in range(beacon_count):
            subprocess.run(command.split(), capture_output=True, text=True, timeout=10)
            if i < beacon_count - 1:
                time.sleep(interval)
        outcome_note = f"{attack_type}_completed"
    except subprocess.TimeoutExpired:
        outcome_note = f"{attack_type}_timed_out"
    except Exception as e:
        print(f"[{session_id}] ERROR: {e}")
        outcome_note = f"{attack_type}_error"
    finally:
        end_ts = now_utc()
        log_attack_session(
            session_id=session_id,
            attack_category="botnet_beacon",
            tool="curl",
            command=f"{command} (x{beacon_count}, every {interval}s)",
            start_ts=start_ts,
            end_ts=end_ts,
            source_ip=SOURCE_IP,
            target_ip=TARGET_IP,
            cloud=CLOUD,
            target_port=80,
            intended_severity=severity,
            notes=outcome_note
        )
        print(f"[{session_id}] Logged. Duration: {(end_ts - start_ts).total_seconds():.2f}s")

if __name__ == "__main__":
    num_sessions = int(sys.argv[1]) if len(sys.argv) > 1 else 5

    for i in range(1, num_sessions + 1):
        if i % 3 == 0:
            # Stealthy: fewer, more widely-spaced beacons
            run_beacon(i, "stealthy_beacon", beacon_count=5, interval=15, severity="stealthy")
        else:
            # Loud: more frequent beacons
            run_beacon(i, "loud_beacon", beacon_count=8, interval=8, severity="loud")
        time.sleep(30)
