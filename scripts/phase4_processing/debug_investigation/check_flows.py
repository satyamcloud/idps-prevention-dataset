import pandas as pd

gcp_df = pd.read_csv("data/processed/gcp_flows.csv")
aws_df = pd.read_csv("data/processed/aws_flows.csv")

print("=== GCP flows ===")
print(f"Total: {len(gcp_df)}")
print(f"\nUnique src_ip values:\n{gcp_df['src_ip'].value_counts()}")
print(f"\nDate range: {pd.to_datetime(gcp_df['bidirectional_first_seen_ms'], unit='ms').min()} to {pd.to_datetime(gcp_df['bidirectional_first_seen_ms'], unit='ms').max()}")

print("\n=== AWS flows ===")
print(f"Total: {len(aws_df)}")
print(f"\nUnique src_ip values:\n{aws_df['src_ip'].value_counts()}")
print(f"\nDate range: {pd.to_datetime(aws_df['bidirectional_first_seen_ms'], unit='ms').min()} to {pd.to_datetime(aws_df['bidirectional_first_seen_ms'], unit='ms').max()}")
