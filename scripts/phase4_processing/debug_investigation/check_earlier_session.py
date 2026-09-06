import json
import pandas as pd

responses = []
with open("data/raw/aws_run_2026-09-04/response_log.json") as f:
    for line in f:
        responses.append(json.loads(line))
responses_df = pd.DataFrame(responses)
responses_df['alert_ts'] = pd.to_datetime(responses_df['alert_timestamp']).dt.tz_localize(None)

# check a wider window covering session 1 and 2
window = responses_df[
    (responses_df['alert_ts'] >= pd.Timestamp("2026-09-04 19:47:55")) &
    (responses_df['alert_ts'] <= pd.Timestamp("2026-09-04 19:49:35")) &
    (responses_df['signature'].str.contains("Sqlmap", na=False))
]
print(window[['alert_ts', 'src_ip', 'signature', 'action']].to_string())
