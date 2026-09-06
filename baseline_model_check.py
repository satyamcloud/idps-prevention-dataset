import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, accuracy_score
from sklearn.preprocessing import LabelEncoder

df = pd.read_csv("data/processed/final_combined_dataset.csv", low_memory=False)
print(f"Total rows: {len(df)}")

# Select genuine NETWORK FEATURES only - exclude anything that would leak the label
feature_cols = [
    'protocol', 'src_port', 'dst_port',
    'bidirectional_duration_ms', 'bidirectional_packets', 'bidirectional_bytes',
    'src2dst_duration_ms', 'src2dst_packets', 'src2dst_bytes',
    'dst2src_duration_ms', 'dst2src_packets', 'dst2src_bytes',
]

target_col = 'action_taken'

model_df = df[feature_cols + [target_col]].dropna(subset=[target_col])
model_df = model_df.dropna()  # drop rows with missing feature values

print(f"Rows after cleaning: {len(model_df)}")
print(f"\nTarget distribution:")
print(model_df[target_col].value_counts())

X = model_df[feature_cols]
y = model_df[target_col]

le = LabelEncoder()
y_encoded = le.fit_transform(y)

X_train, X_test, y_train, y_test = train_test_split(
    X, y_encoded, test_size=0.2, random_state=42, stratify=y_encoded
)

print(f"\nTraining RandomForest on {len(X_train)} rows, testing on {len(X_test)} rows...")
clf = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
clf.fit(X_train, y_train)

y_pred = clf.predict(X_test)
acc = accuracy_score(y_test, y_pred)

print(f"\n{'='*50}")
print(f"OVERALL ACCURACY: {acc:.4f}")
print(f"{'='*50}")
print(f"\nClassification report:")
print(classification_report(y_test, y_pred, target_names=le.classes_))

print(f"\nFeature importances:")
importances = pd.Series(clf.feature_importances_, index=feature_cols).sort_values(ascending=False)
print(importances)
