import pandas as pd

df = pd.read_csv("release_package/RELEASE_dataset_v1.csv", low_memory=False)

print(f"Total rows: {len(df)}")
print(f"Total columns: {len(df.columns)}")

print(f"\nNull counts per column:")
print(df.isnull().sum())

print(f"\nDuplicate rows: {df.duplicated().sum()}")

print(f"\naction_taken value counts:")
print(df['action_taken'].value_counts())

print(f"\nattack_category value counts:")
print(df['attack_category'].value_counts())

print(f"\ncloud value counts:")
print(df['cloud'].value_counts())
