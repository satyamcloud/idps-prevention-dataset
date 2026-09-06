import pandas as pd

for cloud, victim_ip in [("aws", "10.0.9.216"), ("gcp", "10.1.0.2")]:
    print(f"\n{'='*50}")
    print(f"Checking {cloud.upper()} for false positives")
    print(f"{'='*50}")

    df = pd.read_csv(f"data/processed/{cloud}_flows_labeled_final_v2.csv", low_memory=False)

    # benign flows that somehow got an action_taken other than 'none'
    benign_with_action = df[
        (df['attack_category'] == 'benign') &
        (df['action_taken'] != 'none')
    ]
    print(f"Benign flows with a non-'none' action: {len(benign_with_action)}")
    if len(benign_with_action) > 0:
        print(benign_with_action[['src_ip', 'dst_port', 'action_taken', 'response_signature']].to_string())
