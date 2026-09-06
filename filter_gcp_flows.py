import pandas as pd

df = pd.read_csv("data/processed/gcp_flows.csv", low_memory=False)
print(f"Before filtering: {len(df)} flows")

df['flow_start'] = pd.to_datetime(df['bidirectional_first_seen_ms'], unit='ms')

start_window = pd.Timestamp("2026-09-05 11:53:28")
end_window = pd.Timestamp("2026-09-05 16:48:37")

filtered = df[(df['flow_start'] >= start_window) & (df['flow_start'] <= end_window)]
print(f"After filtering to valid run window: {len(filtered)} flows")

filtered.to_csv("data/processed/gcp_flows_filtered.csv", index=False)
print("Saved to data/processed/gcp_flows_filtered.csv")

print(f"\nSrc IP breakdown after filtering:")
print(filtered['src_ip'].value_counts())
