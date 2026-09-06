import pandas as pd
from sklearn.model_selection import GroupShuffleSplit
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, accuracy_score
from sklearn.preprocessing import LabelEncoder

df = pd.read_csv("release_package/RELEASE_dataset_v1.csv", low_memory=False)
print(f"Total rows: {len(df)}")

feature_cols = [
    'protocol', 'src_port', 'dst_port',
    'bidirectional_duration_ms', 'bidirectional_packets', 'bidirectional_bytes',
    'src2dst_duration_ms', 'src2dst_packets', 'src2dst_bytes',
    'dst2src_duration_ms', 'dst2src_packets', 'dst2src_bytes',
]
target_col = 'action_taken'

# Exclude false_positive_prevented from the classification task (too few
# samples for meaningful evaluation - reported separately as a descriptive
# statistic, not a classification target)
model_df = df[df[target_col] != 'false_positive_prevented'].copy()
model_df = model_df.dropna(subset=feature_cols + [target_col, 'session_id'])

print(f"Rows after excluding false_positive_prevented and dropping NaNs: {len(model_df)}")
print(f"\nTarget distribution:")
print(model_df[target_col].value_counts())
print(f"\nUnique sessions: {model_df['session_id'].nunique()}")

X = model_df[feature_cols]
y = model_df[target_col]
groups = model_df['session_id']  # this is what prevents leakage

le = LabelEncoder()
y_encoded = le.fit_transform(y)

# GroupShuffleSplit ensures all flows from one session_id go entirely
# into train OR entirely into test - no leakage
splitter = GroupShuffleSplit(test_size=0.2, n_splits=1, random_state=42)
train_idx, test_idx = next(splitter.split(X, y_encoded, groups=groups))

X_train, X_test = X.iloc[train_idx], X.iloc[test_idx]
y_train, y_test = y_encoded[train_idx], y_encoded[test_idx]

print(f"\nTraining sessions: {groups.iloc[train_idx].nunique()}, Test sessions: {groups.iloc[test_idx].nunique()}")
print(f"Training rows: {len(X_train)}, Test rows: {len(X_test)}")

# Sanity check: confirm zero session overlap between train and test
train_sessions = set(groups.iloc[train_idx])
test_sessions = set(groups.iloc[test_idx])
overlap = train_sessions & test_sessions
print(f"Session overlap between train/test (should be 0): {len(overlap)}")

clf = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
clf.fit(X_train, y_train)

y_pred = clf.predict(X_test)
acc = accuracy_score(y_test, y_pred)

print(f"\n{'='*50}")
print(f"OVERALL ACCURACY (session-level split): {acc:.4f}")
print(f"{'='*50}")
print(f"\nClassification report:")
print(classification_report(y_test, y_pred, target_names=le.classes_))
