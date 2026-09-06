from nfstream import NFStreamer
import pandas as pd
import glob

pcap_files = sorted(glob.glob("data/raw/aws_run_2026-09-04/log.pcap.*"))
for pcap_file in pcap_files:
    streamer = NFStreamer(source=pcap_file)
    df = streamer.to_pandas()
    if len(df) > 0:
        start = pd.to_datetime(df['bidirectional_first_seen_ms'], unit='ms').min()
        end = pd.to_datetime(df['bidirectional_first_seen_ms'], unit='ms').max()
        print(f"{pcap_file}: {len(df)} flows, {start} to {end}")
    else:
        print(f"{pcap_file}: 0 flows")
