import json
import pandas as pd

flows = pd.read_csv("data/processed/aws_flows_labeled_final_v2.csv", low_memory=False)
flows['flow_start'] = pd.to_datetime(flows['flow_start'])

responses = []
with open("data/raw/aws_run_2026-09-04/response_log.json") as f:
    for line in f:
        responses.append(json.loads(line))
responses_df = pd.DataFrame(responses)
responses_df['alert_ts'] = pd.to_datetime(responses_df['alert_timestamp']).dt.tz_localize(None)

protected = responses_df[responses_df['action'] == 'skipped_self_block_protection']
print("Sample protection event timestamps:")
print(protected['alert_ts'].head(5))

victim_benign = flows[(flows['src_ip'] == '10.0.9.216') & (flows['attack_category'] == 'benign')]
print("\nSample benign victim flow timestamps:")
print(victim_benign['flow_start'].head(5))

# check overall date ranges
print(f"\nProtection events date range: {protected['alert_ts'].min()} to {protected['alert_ts'].max()}")
print(f"Benign victim flows date range: {victim_benign['flow_start'].min()} to {victim_benign['flow_start'].max()}")
