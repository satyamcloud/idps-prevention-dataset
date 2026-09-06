import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, accuracy_score
from sklearn.preprocessing import LabelEncoder

df = pd.read_csv("release_package/RELEASE_dataset_v1.csv", low_memory=False)

feature_cols = [
    'protocol', 'src_port', 'dst_port',
    'bidirectional_duration_ms', 'bidirectional_packets', 'bidirectional_bytes',
    'src2dst_duration_ms', 'src2dst_packets', 'src2dst_bytes',
    'dst2src_duration_ms', 'dst2src_packets', 'dst2src_bytes',
]
target_col = 'action_taken'

model_df = df[df[target_col] != 'false_positive_prevented'].copy()
model_df = model_df.dropna(subset=feature_cols + [target_col, 'cloud'])

le = LabelEncoder()
le.fit(model_df[target_col])

def run_cross_cloud(train_cloud, test_cloud):
    train_df = model_df[model_df['cloud'] == train_cloud]
    test_df = model_df[model_df['cloud'] == test_cloud]

    X_train = train_df[feature_cols]
    y_train = le.transform(train_df[target_col])
    X_test = test_df[feature_cols]
    y_test = le.transform(test_df[target_col])

    clf = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
    clf.fit(X_train, y_train)
    y_pred = clf.predict(X_test)
    acc = accuracy_score(y_test, y_pred)

    print(f"\n{'='*60}")
    print(f"TRAIN ON {train_cloud.upper()}, TEST ON {test_cloud.upper()}")
    print(f"{'='*60}")
    print(f"Accuracy: {acc:.4f}")
    print(classification_report(y_test, y_pred, target_names=le.classes_, zero_division=0))

run_cross_cloud('aws', 'gcp')
run_cross_cloud('gcp', 'aws')
