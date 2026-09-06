import pandas as pd
import json

CLOUD = "gcp"
ATTACKER_IP = "10.1.1.2"
VICTIM_IP = "10.1.0.2"

flows = pd.read_csv(f"data/processed/{CLOUD}_flows_filtered.csv", low_memory=False)
flows['flow_start'] = pd.to_datetime(flows['bidirectional_first_seen_ms'], unit='ms')

sessions = []
with open(f"data/raw/{CLOUD}_run_2026-09-05/attack_log.json") as f:
    for line in f:
        sessions.append(json.loads(line))
sessions_df = pd.DataFrame(sessions)
sessions_df['start_ts'] = pd.to_datetime(sessions_df['start_timestamp']).dt.tz_localize(None)
sessions_df['end_ts'] = pd.to_datetime(sessions_df['end_timestamp']).dt.tz_localize(None)
sessions_df['start_ts_buffered'] = sessions_df['start_ts'] - pd.Timedelta(seconds=2)
sessions_df['end_ts_buffered'] = sessions_df['end_ts'] + pd.Timedelta(seconds=2)

flows['session_id'] = None
flows['attack_category'] = 'benign'
flows['intended_severity'] = None
flows['session_notes'] = None

attacker_flows_mask = flows['src_ip'] == ATTACKER_IP
for _, session in sessions_df.iterrows():
    mask = (
        attacker_flows_mask &
        (flows['flow_start'] >= session['start_ts_buffered']) &
        (flows['flow_start'] <= session['end_ts_buffered'])
    )
    if pd.notna(session['target_port']):
        mask = mask & (flows['dst_port'] == session['target_port'])
    flows.loc[mask, 'session_id'] = session['session_id']
    flows.loc[mask, 'attack_category'] = session['attack_category']
    flows.loc[mask, 'intended_severity'] = session['intended_severity']
    flows.loc[mask, 'session_notes'] = session['notes']

print(f"Session-matched flows: {(flows['attack_category'] != 'benign').sum()}")

responses = []
with open(f"data/raw/{CLOUD}_run_2026-09-05/response_log.json") as f:
    for line in f:
        responses.append(json.loads(line))
responses_df = pd.DataFrame(responses)
responses_df['alert_ts'] = pd.to_datetime(responses_df['alert_timestamp']).dt.tz_localize(None)

flows['action_taken'] = 'none'
flows['action_latency_seconds'] = None
flows['response_signature'] = None

attack_flows = flows[flows['session_id'].notna()].copy()
print(f"Matching {len(attack_flows)} attack flows against responses...")

for idx, flow in attack_flows.iterrows():
    src_ip = flow['src_ip']
    flow_start = flow['flow_start']
    candidates = responses_df[
        (responses_df['src_ip'] == src_ip) &
        (responses_df['alert_ts'] >= flow_start - pd.Timedelta(seconds=5)) &
        (responses_df['alert_ts'] <= flow_start + pd.Timedelta(seconds=5))
    ]
    if len(candidates) > 0:
        candidates = candidates.copy()
        candidates['time_diff'] = (candidates['alert_ts'] - flow_start).abs()
        closest = candidates.loc[candidates['time_diff'].idxmin()]
        flows.loc[idx, 'action_taken'] = closest['action']
        flows.loc[idx, 'action_latency_seconds'] = closest['action_latency_seconds']
        flows.loc[idx, 'response_signature'] = closest['signature']

# Block-state reconstruction
flush_times = []
with open(f"data/raw/{CLOUD}_run_2026-09-05/run_log_real.txt") as f:
    for line in f:
        if "Victim iptables flushed" in line:
            ts_str = line.split("]")[0].strip("[")
            flush_times.append(pd.Timestamp(ts_str))

print(f"Found {len(flush_times)} flush events")

block_starts = responses_df[
    (responses_df['src_ip'] == ATTACKER_IP) &
    (responses_df['action'] == 'block_ip')
]['alert_ts'].sort_values().tolist()
flush_times_sorted = sorted(flush_times)

def was_blocked_at(timestamp):
    relevant_blocks = [b for b in block_starts if b <= timestamp]
    if not relevant_blocks:
        return False
    last_block = max(relevant_blocks)
    flushes_between = [f for f in flush_times_sorted if last_block < f <= timestamp]
    return len(flushes_between) == 0

attack_mask = flows['session_id'].notna()
flows.loc[attack_mask, 'was_blocked_at_flow_time'] = flows.loc[attack_mask, 'flow_start'].apply(was_blocked_at)

refined_mask = (flows['action_taken'] == 'none') & (flows['was_blocked_at_flow_time'] == True)
flows.loc[refined_mask, 'action_taken'] = 'blocked_no_new_alert'

print(f"\nRefined {refined_mask.sum()} flows to 'blocked_no_new_alert'")
print(f"\nFinal breakdown BY category:")
print(pd.crosstab(flows['attack_category'], flows['action_taken']))

flows.to_csv(f"data/processed/{CLOUD}_flows_labeled_final_v2.csv", index=False)
print(f"\nSaved to data/processed/{CLOUD}_flows_labeled_final_v2.csv")
