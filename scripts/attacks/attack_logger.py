#!/usr/bin/env python3
"""
Shared logging helper for all attack scripts.
Import this in every attack script (recon, bruteforce, dos, web, botnet)
to ensure consistent attack_log.json format across all categories.
"""
import json
import datetime
import os

LOG_PATH = "/home/ubuntu/attack_log.json"

def log_attack_session(session_id, attack_category, tool, command,
                        start_ts, end_ts, source_ip, target_ip,
                        cloud, target_port=None, intended_severity="loud",
                        notes=""):
    entry = {
        "session_id": session_id,
        "attack_category": attack_category,
        "tool": tool,
        "command": command,
        "start_timestamp": start_ts.isoformat(),
        "end_timestamp": end_ts.isoformat(),
        "source_ip": source_ip,
        "target_ip": target_ip,
        "target_port": target_port,
        "cloud": cloud,
        "intended_severity": intended_severity,
        "notes": notes
    }
    with open(LOG_PATH, "a") as f:
        f.write(json.dumps(entry) + "\n")
    return entry

def now_utc():
    return datetime.datetime.now(datetime.timezone.utc)
