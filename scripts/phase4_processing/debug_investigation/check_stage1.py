import pandas as pd
df = pd.read_csv("data/processed/aws_flows_labeled_stage1.csv", low_memory=False)

benign = df[df['attack_category'] == 'benign']
print("Benign flows src_ip breakdown:")
print(benign['src_ip'].value_counts())
print("\nBenign flows dst_port breakdown:")
print(benign['dst_port'].value_counts().head(10))
