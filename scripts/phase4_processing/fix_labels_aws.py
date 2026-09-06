import pandas as pd
import json

CLOUD = "aws"

flows = pd.read_csv(f"data/processed/{CLOUD}_flows_labeled_final.csv", low_memory=False)
flows['flow_start'] = pd.to_datetime(flows['flow_start'])

# Load response log again, and also load the master run log to find flush timestamps
responses = []
with open(f"data/raw/{CLOUD}_run_2026-09-04/response_log.json") as f:
    for line in f:
        responses.append(json.loads(line))
responses_df = pd.DataFrame(responses)
responses_df['alert_ts'] = pd.to_datetime(responses_df['alert_timestamp']).dt.tz_localize(None)

# Get flush timestamps from run_log (category transitions = flush points)
flush_times = []
with open(f"data/raw/{CLOUD}_run_2026-09-04/run_log_real.txt") as f:
    for line in f:
        if "Victim iptables flushed" in line:
            ts_str = line.split("]")[0].strip("[")
            flush_times.append(pd.Timestamp(ts_str))

print(f"Found {len(flush_times)} flush events")

# For each attack IP, build a sorted timeline of block_ip events (block starts)
# and flush events (block ends) to determine "was blocked" at any timestamp
attacker_ip = "10.0.16.175"
block_starts = responses_df[
    (responses_df['src_ip'] == attacker_ip) &
    (responses_df['action'] == 'block_ip')
]['alert_ts'].sort_values().tolist()

flush_times_sorted = sorted(flush_times)

def was_blocked_at(timestamp):
    # find the most recent block_start before this timestamp
    relevant_blocks = [b for b in block_starts if b <= timestamp]
    if not relevant_blocks:
        return False
    last_block = max(relevant_blocks)
    # find if a flush happened between last_block and timestamp
    flushes_between = [f for f in flush_times_sorted if last_block < f <= timestamp]
    return len(flushes_between) == 0

print("Computing block-state for each attack flow (this may take a few minutes)...")
attack_mask = flows['session_id'].notna()
flows.loc[attack_mask, 'was_blocked_at_flow_time'] = flows.loc[attack_mask, 'flow_start'].apply(was_blocked_at)

# Refine action_taken: if action was 'none' but IP was actually blocked, relabel
refined_mask = (flows['action_taken'] == 'none') & (flows['was_blocked_at_flow_time'] == True)
flows.loc[refined_mask, 'action_taken'] = 'blocked_no_new_alert'

print(f"\nRefined {refined_mask.sum()} flows from 'none' to 'blocked_no_new_alert'")

print(f"\nFinal action_taken breakdown BY category:")
print(pd.crosstab(flows['attack_category'], flows['action_taken']))

flows.to_csv(f"data/processed/{CLOUD}_flows_labeled_final_v2.csv", index=False)
print(f"\nSaved to data/processed/{CLOUD}_flows_labeled_final_v2.csv")
