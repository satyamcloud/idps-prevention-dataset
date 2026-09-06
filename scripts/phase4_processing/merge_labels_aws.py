import pandas as pd
import json

CLOUD = "aws"
ATTACKER_IP = "10.0.16.175"
VICTIM_IP = "10.0.9.216"

# Load flows
flows = pd.read_csv(f"data/processed/{CLOUD}_flows_filtered.csv", low_memory=False)
flows['flow_start'] = pd.to_datetime(flows['bidirectional_first_seen_ms'], unit='ms')
flows['flow_end'] = pd.to_datetime(flows['bidirectional_last_seen_ms'], unit='ms')

print(f"Total flows loaded: {len(flows)}")

# Load attack sessions
sessions = []
with open(f"data/raw/{CLOUD}_run_2026-09-04/attack_log.json") as f:
    for line in f:
        sessions.append(json.loads(line))
sessions_df = pd.DataFrame(sessions)
sessions_df['start_ts'] = pd.to_datetime(sessions_df['start_timestamp']).dt.tz_localize(None)
sessions_df['end_ts'] = pd.to_datetime(sessions_df['end_timestamp']).dt.tz_localize(None)
# small buffer for command startup/teardown overhead
sessions_df['start_ts_buffered'] = sessions_df['start_ts'] - pd.Timedelta(seconds=2)
sessions_df['end_ts_buffered'] = sessions_df['end_ts'] + pd.Timedelta(seconds=2)

print(f"Total sessions loaded: {len(sessions_df)}")

# Load response actions
responses = []
with open(f"data/raw/{CLOUD}_run_2026-09-04/response_log.json") as f:
    for line in f:
        responses.append(json.loads(line))
responses_df = pd.DataFrame(responses)
responses_df['alert_ts'] = pd.to_datetime(responses_df['alert_timestamp']).dt.tz_localize(None)

print(f"Total response actions loaded: {len(responses_df)}")

# Initialize label columns
flows['session_id'] = None
flows['attack_category'] = 'benign'
flows['intended_severity'] = None
flows['session_notes'] = None

# Match flows to sessions (attacker-initiated flows only)
attacker_flows_mask = flows['src_ip'] == ATTACKER_IP

for _, session in sessions_df.iterrows():
    mask = (
        attacker_flows_mask &
        (flows['flow_start'] >= session['start_ts_buffered']) &
        (flows['flow_start'] <= session['end_ts_buffered'])
    )
    # if session has a specific target port, further restrict
    if pd.notna(session['target_port']):
        mask = mask & (flows['dst_port'] == session['target_port'])

    flows.loc[mask, 'session_id'] = session['session_id']
    flows.loc[mask, 'attack_category'] = session['attack_category']
    flows.loc[mask, 'intended_severity'] = session['intended_severity']
    flows.loc[mask, 'session_notes'] = session['notes']

print(f"\nFlows matched to a session: {(flows['attack_category'] != 'benign').sum()}")
print(f"Flows remaining benign/unmatched: {(flows['attack_category'] == 'benign').sum()}")

print(f"\nBreakdown by attack_category:")
print(flows['attack_category'].value_counts())

flows.to_csv(f"data/processed/{CLOUD}_flows_labeled_stage1.csv", index=False)
print(f"\nSaved stage 1 (session-matched) to data/processed/{CLOUD}_flows_labeled_stage1.csv")
