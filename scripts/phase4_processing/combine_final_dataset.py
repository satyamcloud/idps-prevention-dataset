import pandas as pd

aws = pd.read_csv("data/processed/aws_flows_labeled_final_v3.csv", low_memory=False)
gcp = pd.read_csv("data/processed/gcp_flows_labeled_final_v3.csv", low_memory=False)

aws['cloud'] = 'aws'
gcp['cloud'] = 'gcp'

combined = pd.concat([aws, gcp], ignore_index=True)

print(f"AWS flows: {len(aws)}")
print(f"GCP flows: {len(gcp)}")
print(f"Combined total: {len(combined)}")

combined.to_csv("data/processed/final_combined_dataset.csv", index=False)
print(f"\nSaved to data/processed/final_combined_dataset.csv")

print(f"\n{'='*60}")
print("FINAL STATISTICS TABLE — Flow counts by category x cloud x outcome")
print(f"{'='*60}")

stats = combined.groupby(['attack_category', 'cloud', 'action_taken']).size().unstack(fill_value=0)
print(stats)

print(f"\n{'='*60}")
print("SUMMARY — Total flows by category")
print(f"{'='*60}")
print(combined['attack_category'].value_counts())

print(f"\n{'='*60}")
print("SUMMARY — Total flows by cloud")
print(f"{'='*60}")
print(combined['cloud'].value_counts())
