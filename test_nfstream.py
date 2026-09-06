from nfstream import NFStreamer
import pandas as pd

pcap_path = "data/raw/gcp_run_2026-09-05/log.pcap.1788577805"

streamer = NFStreamer(source=pcap_path)
df = streamer.to_pandas()

print(f"Total flows extracted: {len(df)}")
print(f"\nColumns available ({len(df.columns)}):")
print(list(df.columns))
print(f"\nFirst few rows:")
print(df.head())
