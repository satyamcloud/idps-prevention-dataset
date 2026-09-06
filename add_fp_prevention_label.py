import pandas as pd
import json

for cloud, run_date, victim_ip in [("aws", "2026-09-04", "10.0.9.216"), ("gcp", "2026-09-05", "10.1.0.2")]:
    print(f"\n{'='*50}")
    print(f"Processing {cloud.upper()}")
    print(f"{'='*50}")

    flows = pd.read_csv(f"data/processed/{cloud}_flows_labeled_final_v2.csv", low_memory=False)
    flows['flow_start'] = pd.to_datetime(flows['flow_start'])

    responses = []
    with open(f"data/raw/{cloud}_run_{run_date}/response_log.json") as f:
        for line in f:
            responses.append(json.loads(line))
    responses_df = pd.DataFrame(responses)
    responses_df['alert_ts'] = pd.to_datetime(responses_df['alert_timestamp']).dt.tz_localize(None)

    protected = responses_df[responses_df['action'] == 'skipped_self_block_protection']
    print(f"Protection events to match: {len(protected)}")

    # match protection events to benign victim-side flows
    victim_benign_flows = flows[
        (flows['src_ip'] == victim_ip) &
        (flows['attack_category'] == 'benign')
    ].copy()
    print(f"Candidate victim benign flows: {len(victim_benign_flows)}")

    matched_count = 0
    for _, event in protected.iterrows():
        alert_ts = event['alert_ts']
        mask = (
            (flows['src_ip'] == victim_ip) &
            (flows['attack_category'] == 'benign') &
            (flows['flow_start'] >= alert_ts - pd.Timedelta(seconds=3)) &
            (flows['flow_start'] <= alert_ts + pd.Timedelta(seconds=3))
        )
        if mask.sum() > 0:
            flows.loc[mask, 'action_taken'] = 'false_positive_prevented'
            flows.loc[mask, 'response_signature'] = event['signature']
            matched_count += mask.sum()

    print(f"Flows relabeled as false_positive_prevented: {matched_count}")

    flows.to_csv(f"data/processed/{cloud}_flows_labeled_final_v3.csv", index=False)
    print(f"Saved to data/processed/{cloud}_flows_labeled_final_v3.csv")

    print(f"\nFinal action_taken distribution:")
    print(flows['action_taken'].value_counts())
