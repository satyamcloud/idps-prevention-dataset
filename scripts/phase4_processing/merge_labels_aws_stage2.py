import pandas as pd
import json

CLOUD = "aws"

flows = pd.read_csv(f"data/processed/{CLOUD}_flows_labeled_stage1.csv", low_memory=False)
flows['flow_start'] = pd.to_datetime(flows['flow_start'])
flows['flow_end'] = pd.to_datetime(flows['flow_end'])

responses = []
with open(f"data/raw/{CLOUD}_run_2026-09-04/response_log.json") as f:
    for line in f:
        responses.append(json.loads(line))
responses_df = pd.DataFrame(responses)
responses_df['alert_ts'] = pd.to_datetime(responses_df['alert_timestamp']).dt.tz_localize(None)

print(f"Total response entries: {len(responses_df)}")

# Initialize new columns
flows['action_taken'] = 'none'
flows['action_latency_seconds'] = None
flows['response_signature'] = None

# For each attack flow (has a session_id), find the closest response
# action from the same source IP within a reasonable time window
attack_flows = flows[flows['session_id'].notna()].copy()
print(f"Attack flows to match against responses: {len(attack_flows)}")

# Group responses by src_ip for faster lookup
for idx, flow in attack_flows.iterrows():
    src_ip = flow['src_ip']
    flow_start = flow['flow_start']

    # find responses from same src_ip, with alert_ts within
    # a window around this flow's start (+/- 5 seconds)
    candidates = responses_df[
        (responses_df['src_ip'] == src_ip) &
        (responses_df['alert_ts'] >= flow_start - pd.Timedelta(seconds=5)) &
        (responses_df['alert_ts'] <= flow_start + pd.Timedelta(seconds=5))
    ]

    if len(candidates) > 0:
        # take the closest one in time
        candidates = candidates.copy()
        candidates['time_diff'] = (candidates['alert_ts'] - flow_start).abs()
        closest = candidates.loc[candidates['time_diff'].idxmin()]
        flows.loc[idx, 'action_taken'] = closest['action']
        flows.loc[idx, 'action_latency_seconds'] = closest['action_latency_seconds']
        flows.loc[idx, 'response_signature'] = closest['signature']

print(f"\nAction taken breakdown (attack flows only):")
print(flows[flows['session_id'].notna()]['action_taken'].value_counts())

flows.to_csv(f"data/processed/{CLOUD}_flows_labeled_final.csv", index=False)
print(f"\nSaved final labeled dataset to data/processed/{CLOUD}_flows_labeled_final.csv")
