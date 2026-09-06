import pandas as pd
df = pd.read_csv("data/processed/aws_flows_labeled_final.csv", low_memory=False)

web = df[df['session_id'] == 'webattack_aws_002'][['session_id', 'flow_start', 'dst_port', 'action_taken', 'response_signature']]
print(web.to_string())
