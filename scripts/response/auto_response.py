#!/usr/bin/env python3
import subprocess
import json
import datetime

EVE_LOG = "/var/log/suricata/eve.json"
RESPONSE_LOG = "/home/ubuntu/response_log.json"

# Never auto-block our own infrastructure, regardless of what an alert's
# src_ip field says (some signatures fire on server-side response traffic,
# not attacker-originated traffic - e.g. "FTP Brute-Force attempt response")
KNOWN_SAFE_IPS = {"10.0.9.216", "122.161.78.71"}  # victim's own private IP

def is_ip_blocked(ip):
    """Check actual iptables state instead of trusting in-memory cache."""
    result = subprocess.run(
        ["iptables", "-C", "INPUT", "-s", ip, "-j", "DROP"],
        capture_output=True
    )
    return result.returncode == 0

def block_ip(ip):
    subprocess.run(["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"], check=True)

def log_response(entry):
    with open(RESPONSE_LOG, "a") as f:
        f.write(json.dumps(entry) + "\n")

def parse_ts(ts_str):
    return datetime.datetime.strptime(ts_str, "%Y-%m-%dT%H:%M:%S.%f%z")

def main():
    proc = subprocess.Popen(
        ["tail", "-F", "-n0", EVE_LOG],
        stdout=subprocess.PIPE,
        text=True,
        bufsize=1
    )
    print("Auto-response script started (stateless - checks live iptables state each time)...")
    for line in proc.stdout:
        line = line.strip()
        if not line:
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        if event.get("event_type") != "alert":
            continue

        src_ip = event.get("src_ip")
        alert_ts_str = event.get("timestamp")
        signature = event.get("alert", {}).get("signature")
        signature_id = event.get("alert", {}).get("signature_id")

        if not src_ip:
            continue

        response_time = datetime.datetime.now(datetime.timezone.utc)

        if src_ip in KNOWN_SAFE_IPS:
            action = "skipped_self_block_protection"
        elif is_ip_blocked(src_ip):
            action = "already_blocked"
        else:
            try:
                block_ip(src_ip)
                action = "block_ip"
            except subprocess.CalledProcessError as e:
                action = "block_failed"
                print(f"Failed to block {src_ip}: {e}")

        try:
            alert_time = parse_ts(alert_ts_str)
            latency = (response_time - alert_time).total_seconds()
        except Exception:
            latency = None

        entry = {
            "response_timestamp": response_time.isoformat(),
            "alert_timestamp": alert_ts_str,
            "src_ip": src_ip,
            "signature": signature,
            "signature_id": signature_id,
            "action": action,
            "action_latency_seconds": latency
        }
        log_response(entry)
        print(f"[{action}] {src_ip} - {signature} (latency: {latency}s)")

if __name__ == "__main__":
    main()
