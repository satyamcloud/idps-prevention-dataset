import pandas as pd

df = pd.read_csv("data/processed/final_combined_dataset.csv", low_memory=False)
print(f"Current columns ({len(df.columns)}):")
print(list(df.columns))

# Organize into clear groups for the released dataset
identifier_cols = ['id', 'cloud', 'session_id', 'source_pcap_file']

network_5tuple_cols = ['src_ip', 'src_port', 'dst_ip', 'dst_port', 'protocol', 'ip_version']

flow_feature_cols = [
    'bidirectional_first_seen_ms', 'bidirectional_last_seen_ms', 'bidirectional_duration_ms',
    'bidirectional_packets', 'bidirectional_bytes',
    'src2dst_first_seen_ms', 'src2dst_last_seen_ms', 'src2dst_duration_ms',
    'src2dst_packets', 'src2dst_bytes',
    'dst2src_first_seen_ms', 'dst2src_last_seen_ms', 'dst2src_duration_ms',
    'dst2src_packets', 'dst2src_bytes',
    'application_name', 'application_category_name', 'application_confidence',
]

label_cols = [
    'attack_category', 'intended_severity', 'session_notes',
    'action_taken', 'action_latency_seconds', 'response_signature',
    'was_blocked_at_flow_time'
]

# Check for any columns we're missing/dropping
all_kept = identifier_cols + network_5tuple_cols + flow_feature_cols + label_cols
dropped = [c for c in df.columns if c not in all_kept]
print(f"\nColumns being DROPPED from final release ({len(dropped)}):")
print(dropped)

final_cols = [c for c in all_kept if c in df.columns]
final_df = df[final_cols]

final_df.to_csv("data/processed/RELEASE_dataset_v1.csv", index=False)
print(f"\nFinal released dataset: {len(final_df)} rows, {len(final_df.columns)} columns")
print(f"Saved to data/processed/RELEASE_dataset_v1.csv")
print(f"\nColumn order:")
for c in final_cols:
    print(f"  - {c}")
