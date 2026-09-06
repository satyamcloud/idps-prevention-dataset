import pandas as pd
df = pd.read_csv("data/processed/aws_flows_labeled_final.csv", low_memory=False)

web = df[df['attack_category'] == 'web_attack']
print(f"Total web_attack flows: {len(web)}")
print(f"\nSession IDs represented:")
print(web['session_id'].value_counts())
print(f"\nSample flow_start times for 'none' action flows:")
print(web[web['action_taken'] == 'none'][['session_id', 'flow_start', 'dst_port']].head(10))
