from nfstream import NFStreamer
import pandas as pd
import glob
import os

def process_cloud(cloud_name, pcap_dir):
    pcap_files = glob.glob(f"{pcap_dir}/log.pcap.*")
    print(f"\n{'='*50}")
    print(f"Processing {cloud_name}: {len(pcap_files)} pcap files found")
    print(f"{'='*50}")

    all_dfs = []
    for pcap_file in sorted(pcap_files):
        print(f"Processing: {pcap_file}")
        try:
            streamer = NFStreamer(source=pcap_file)
            df = streamer.to_pandas()
            df['source_pcap_file'] = os.path.basename(pcap_file)
            all_dfs.append(df)
            print(f"  -> {len(df)} flows extracted")
        except Exception as e:
            print(f"  !!! ERROR processing {pcap_file}: {e}")

    if all_dfs:
        combined = pd.concat(all_dfs, ignore_index=True)
        combined['cloud'] = cloud_name
        output_path = f"data/processed/{cloud_name}_flows.csv"
        os.makedirs("data/processed", exist_ok=True)
        combined.to_csv(output_path, index=False)
        print(f"\n{cloud_name} TOTAL: {len(combined)} flows saved to {output_path}")
        return combined
    return None

gcp_df = process_cloud("gcp", "data/raw/gcp_run_2026-09-05")
aws_df = process_cloud("aws", "data/raw/aws_run_2026-09-04")

print(f"\n{'='*50}")
print("SUMMARY")
print(f"{'='*50}")
if gcp_df is not None:
    print(f"GCP total flows: {len(gcp_df)}")
if aws_df is not None:
    print(f"AWS total flows: {len(aws_df)}")
