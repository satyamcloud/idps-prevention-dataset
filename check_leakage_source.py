import pandas as pd

df = pd.read_csv("data/processed/final_combined_dataset.csv", low_memory=False)

print("Category breakdown WITHIN each action_taken class:")
print(pd.crosstab(df['action_taken'], df['attack_category']))
