import json
import pandas as pd

for cloud, run_date in [("aws", "2026-09-04"), ("gcp", "2026-09-05")]:
    print(f"\n{'='*50}")
    print(f"{cloud.upper()} self-block-protection events")
    print(f"{'='*50}")

    responses = []
    with open(f"data/raw/{cloud}_run_{run_date}/response_log.json") as f:
        for line in f:
            responses.append(json.loads(line))
    df = pd.DataFrame(responses)

    protected = df[df['action'] == 'skipped_self_block_protection']
    print(f"Total skipped_self_block_protection events: {len(protected)}")
    print(f"\nSignature breakdown:")
    print(protected['signature'].value_counts())
