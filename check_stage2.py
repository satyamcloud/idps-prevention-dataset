import pandas as pd
df = pd.read_csv("data/processed/aws_flows_labeled_final.csv", low_memory=False)

print("Action taken breakdown BY attack category:")
print(pd.crosstab(df['attack_category'], df['action_taken']))
