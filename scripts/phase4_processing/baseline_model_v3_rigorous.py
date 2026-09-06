import pandas as pd
import sklearn
from sklearn.model_selection import GroupKFold
from sklearn.ensemble import RandomForestClassifier
from sklearn.dummy import DummyClassifier
from sklearn.metrics import classification_report, accuracy_score
from sklearn.preprocessing import LabelEncoder
import numpy as np

print(f"scikit-learn version: {sklearn.__version__}")
print(f"pandas version: {pd.__version__}")
print(f"numpy version: {np.__version__}")

RANDOM_SEED = 42
N_FOLDS = 5

df = pd.read_csv("release_package/RELEASE_dataset_v1.csv", low_memory=False)

feature_cols = [
    'protocol', 'src_port', 'dst_port',
    'bidirectional_duration_ms', 'bidirectional_packets', 'bidirectional_bytes',
    'src2dst_duration_ms', 'src2dst_packets', 'src2dst_bytes',
    'dst2src_duration_ms', 'dst2src_packets', 'dst2src_bytes',
]
target_col = 'action_taken'

model_df = df[df[target_col] != 'false_positive_prevented'].copy()
model_df = model_df.dropna(subset=feature_cols + [target_col, 'session_id'])

X = model_df[feature_cols].reset_index(drop=True)
y_raw = model_df[target_col].reset_index(drop=True)
groups = model_df['session_id'].reset_index(drop=True)

le = LabelEncoder()
y = le.fit_transform(y_raw)

print(f"\nTotal rows: {len(X)}, Unique sessions: {groups.nunique()}")
print(f"Class distribution:\n{y_raw.value_counts()}")

gkf = GroupKFold(n_splits=N_FOLDS)

rf_accuracies = []
dummy_accuracies = []
all_reports = []

for fold_idx, (train_idx, test_idx) in enumerate(gkf.split(X, y, groups=groups)):
    X_train, X_test = X.iloc[train_idx], X.iloc[test_idx]
    y_train, y_test = y[train_idx], y[test_idx]

    # Explicit hyperparameters, documented
    clf = RandomForestClassifier(
        n_estimators=100,
        max_depth=None,
        min_samples_split=2,
        min_samples_leaf=1,
        random_state=RANDOM_SEED,
        n_jobs=-1
    )
    clf.fit(X_train, y_train)
    y_pred = clf.predict(X_test)
    rf_acc = accuracy_score(y_test, y_pred)
    rf_accuracies.append(rf_acc)

    # Majority-class baseline for comparison
    dummy = DummyClassifier(strategy="most_frequent", random_state=RANDOM_SEED)
    dummy.fit(X_train, y_train)
    y_dummy_pred = dummy.predict(X_test)
    dummy_acc = accuracy_score(y_test, y_dummy_pred)
    dummy_accuracies.append(dummy_acc)

    print(f"\n=== Fold {fold_idx+1}/{N_FOLDS} ===")
    print(f"Train sessions: {groups.iloc[train_idx].nunique()}, Test sessions: {groups.iloc[test_idx].nunique()}")
    print(f"RandomForest accuracy: {rf_acc:.4f}")
    print(f"Majority-class baseline accuracy: {dummy_acc:.4f}")
    report = classification_report(y_test, y_pred, target_names=le.classes_, zero_division=0)
    print(report)
    all_reports.append(report)

print(f"\n{'='*60}")
print(f"CROSS-VALIDATION SUMMARY ({N_FOLDS}-fold, grouped by session)")
print(f"{'='*60}")
print(f"RandomForest accuracy: mean={np.mean(rf_accuracies):.4f}, std={np.std(rf_accuracies):.4f}")
print(f"  Per-fold: {[f'{a:.4f}' for a in rf_accuracies]}")
print(f"Majority-class baseline accuracy: mean={np.mean(dummy_accuracies):.4f}, std={np.std(dummy_accuracies):.4f}")
print(f"  Per-fold: {[f'{a:.4f}' for a in dummy_accuracies]}")
print(f"\nHyperparameters: n_estimators=100, max_depth=None, min_samples_split=2, min_samples_leaf=1, random_state={RANDOM_SEED}")
