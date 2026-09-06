import pandas as pd
import json

for cloud, date in [("aws", "2026-09-04"), ("gcp", "2026-09-05")]:
    print(f"\n{'='*60}")
    print(f"{cloud.upper()} - action_taken distribution by window size")
    print(f"{'='*60}")

    sessions = []
    with open(f"data/raw/{cloud}_run_{date}/attack_log.json") as f:
        for line in f:
            sessions.append(json.loads(line))
    sessions_df = pd.DataFrame(sessions)
    sessions_df['start_ts'] = pd.to_datetime(sessions_df['start_timestamp']).dt.tz_localize(None)

    responses = []
    with open(f"data/raw/{cloud}_run_{date}/response_log.json") as f:
        for line in f:
            responses.append(json.loads(line))
    responses_df = pd.DataFrame(responses)
    responses_df['alert_ts'] = pd.to_datetime(responses_df['alert_timestamp']).dt.tz_localize(None)

    attacker_ip = "10.0.16.175" if cloud == "aws" else "10.1.1.2"

    for window_seconds in [1, 3, 5, 10]:
        # For each session, does a response exist within this window of session start?
        matched = 0
        for _, sess in sessions_df.iterrows():
            candidates = responses_df[
                (responses_df['src_ip'] == attacker_ip) &
                (responses_df['alert_ts'] >= sess['start_ts'] - pd.Timedelta(seconds=window_seconds)) &
                (responses_df['alert_ts'] <= sess['start_ts'] + pd.Timedelta(seconds=window_seconds))
            ]
            if len(candidates) > 0:
                matched += 1
        print(f"Window +/-{window_seconds}s: {matched}/{len(sessions_df)} sessions have a matched response event ({100*matched/len(sessions_df):.1f}%)")
