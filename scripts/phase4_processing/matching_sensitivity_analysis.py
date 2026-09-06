import pandas as pd
import json

for cloud, run_date in [("aws", "2026-09-04"), ("gcp", "2026-09-05")]:
    print(f"\n{'='*60}")
    print(f"{cloud.upper()} - Matching sensitivity analysis")
    print(f"{'='*60}")

    # Load raw sessions and responses fresh
    sessions = []
    with open(f"data/raw/{cloud}_run_{'2026-09-04' if cloud=='aws' else '2026-09-05'}/attack_log.json") as f:
        for line in f:
            sessions.append(json.loads(line))
    sessions_df = pd.DataFrame(sessions)
    sessions_df['start_ts'] = pd.to_datetime(sessions_df['start_timestamp']).dt.tz_localize(None)
    sessions_df['end_ts'] = pd.to_datetime(sessions_df['end_timestamp']).dt.tz_localize(None)

    responses = []
    with open(f"data/raw/{cloud}_run_{'2026-09-04' if cloud=='aws' else '2026-09-05'}/response_log.json") as f:
        for line in f:
            responses.append(json.loads(line))
    responses_df = pd.DataFrame(responses)
    responses_df['alert_ts'] = pd.to_datetime(responses_df['alert_timestamp']).dt.tz_localize(None)

    # --- Check 1: session boundary ambiguity ---
    # For each session, check if the NEXT session for the same src_ip
    # starts before this session's end_ts + 2s buffer (i.e. could a flow
    # near the boundary match BOTH sessions?)
    sessions_sorted = sessions_df.sort_values('start_ts').reset_index(drop=True)
    ambiguous_count = 0
    for i in range(len(sessions_sorted) - 1):
        this_end_buffered = sessions_sorted.loc[i, 'end_ts'] + pd.Timedelta(seconds=2)
        next_start_buffered = sessions_sorted.loc[i+1, 'start_ts'] - pd.Timedelta(seconds=2)
        if this_end_buffered >= next_start_buffered:
            ambiguous_count += 1
    print(f"Sessions with boundary overlap (ambiguous flow-to-session matching): {ambiguous_count} / {len(sessions_sorted)}")

    # --- Check 2: response-matching window sensitivity ---
    for window_seconds in [1, 3, 5, 10]:
        multi_match_count = 0
        for _, resp in responses_df.iterrows():
            candidates = sessions_df[
                (sessions_df['start_ts'] - pd.Timedelta(seconds=window_seconds) <= resp['alert_ts']) &
                (sessions_df['end_ts'] + pd.Timedelta(seconds=window_seconds) >= resp['alert_ts'])
            ]
            if len(candidates) > 1:
                multi_match_count += 1
        print(f"Window +/-{window_seconds}s: {multi_match_count}/{len(responses_df)} response events have multiple candidate session matches ({100*multi_match_count/len(responses_df):.2f}%)")
