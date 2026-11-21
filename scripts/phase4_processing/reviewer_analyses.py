"""Additional analyses requested during peer review (macro-F1, balanced accuracy,
PR-AUC, category-only baseline, port ablation, three-class, within-category,
event-level latency, session coverage). Run from the repository root:
    python scripts/phase4_processing/reviewer_analyses.py release_package/RELEASE_dataset_v1.csv \
        scripts/phase4_processing/validation_results/reviewer_analyses_results.json
Uses the same features, GroupKFold(5) by session_id, RF(n_estimators=100, random_state=42)
as scripts/phase4_processing/baseline_model_v3_rigorous.py.
Note: the fold assignment of GroupKFold depends on the scikit-learn version. The paper's tables were produced
with scikit-learn 1.9.x; with 1.7.2 eight block_ip flows fall in a different fold and the RF macro-F1 is 94.0%
instead of 95.0% (accuracy 99.62% vs 99.61%). Use scikit-learn 1.9.x to reproduce the paper's numbers exactly."""
import sys, json, warnings
import numpy as np, pandas as pd
from sklearn.model_selection import GroupKFold
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, f1_score, balanced_accuracy_score, average_precision_score
from sklearn.preprocessing import LabelEncoder
warnings.filterwarnings("ignore")
src, out = sys.argv[1], sys.argv[2]
df = pd.read_csv(src, low_memory=False)
F = ['protocol','src_port','dst_port','bidirectional_duration_ms','bidirectional_packets','bidirectional_bytes',
     'src2dst_duration_ms','src2dst_packets','src2dst_bytes','dst2src_duration_ms','dst2src_packets','dst2src_bytes']
NOPORT = [f for f in F if f not in ('src_port','dst_port')]
m = df[df.action_taken != 'false_positive_prevented'].dropna(subset=F+['action_taken','session_id']).reset_index(drop=True)
le = LabelEncoder(); y = le.fit_transform(m.action_taken); cls = list(le.classes_)
AB = cls.index('already_blocked')
def ms(v): return [float(np.mean(v)), float(np.std(v))]
def cv(feats, mask=None):
    idx = np.arange(len(m)) if mask is None else np.where(mask)[0]
    X = m.loc[idx, feats].reset_index(drop=True); yy = y[idx]; g = m.session_id.iloc[idx].reset_index(drop=True)
    acc, maf, bal, ap = [], [], [], {}
    for tr, te in GroupKFold(n_splits=5).split(X, yy, groups=g):
        clf = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1).fit(X.iloc[tr], yy[tr])
        p = clf.predict(X.iloc[te]); yt = yy[te]; pr = clf.predict_proba(X.iloc[te])
        acc.append(accuracy_score(yt, p)); bal.append(balanced_accuracy_score(yt, p))
        maf.append(f1_score(yt, p, labels=np.unique(yt), average='macro', zero_division=0))
        for j, c in enumerate(clf.classes_):
            if c != AB and (yt == c).sum() > 0:
                ap.setdefault(cls[c], []).append(average_precision_score(yt == c, pr[:, j]))
    return dict(acc=ms(acc), macro_f1=ms(maf), bal_acc=ms(bal), ap={k: ms(v)+[len(v)] for k, v in ap.items()})
R = {}
R['rf_all'] = cv(F)
R['rf_noport'] = cv(NOPORT)
R['rf_no_src_port'] = cv([f for f in F if f != 'src_port'])
R['rf_no_dst_port'] = cv([f for f in F if f != 'dst_port'])
nn = (m.action_taken != 'none').values
R['rf3_all'] = cv(F, nn); R['rf3_noport'] = cv(NOPORT, nn)
gk = GroupKFold(n_splits=5); maj, majf, majb, ca, cf, cb = [], [], [], [], [], []
for tr, te in gk.split(m[F], y, groups=m.session_id):
    c = np.bincount(y[tr]).argmax(); p = np.full(len(te), c)
    maj.append(accuracy_score(y[te], p)); majb.append(balanced_accuracy_score(y[te], p))
    majf.append(f1_score(y[te], p, labels=np.unique(y[te]), average='macro', zero_division=0))
    tab = pd.crosstab(m.attack_category.iloc[tr], y[tr]); mp = tab.idxmax(axis=1).to_dict()
    p = m.attack_category.iloc[te].map(mp).fillna(np.bincount(y[tr]).argmax()).astype(int).values
    ca.append(accuracy_score(y[te], p)); cb.append(balanced_accuracy_score(y[te], p))
    cf.append(f1_score(y[te], p, labels=np.unique(y[te]), average='macro', zero_division=0))
R['majority'] = dict(acc=ms(maj), macro_f1=ms(majf), bal_acc=ms(majb))
R['category_lookup'] = dict(acc=ms(ca), macro_f1=ms(cf), bal_acc=ms(cb))
R['within'] = {}
for cat in ['dos_volumetric','bruteforce','web_attack','reconnaissance']:
    mk = (m.attack_category == cat).values
    R['within'][cat] = dict(counts=m[mk].action_taken.value_counts().to_dict(), sessions=int(m[mk].session_id.nunique()),
                            all=cv(F, mk), noport=cv(NOPORT, mk))
# event-level latency (distinct response events approximated by distinct cloud/latency/signature/action)
l = df[df.action_latency_seconds.notna()].copy(); l['ms'] = l.action_latency_seconds*1000
key = ['cloud','action_latency_seconds','response_signature','action_taken']
e = l.drop_duplicates(key)
def st(g): return dict(flows=int(len(g)), events=None)
R['latency'] = dict(
    flow_mean=float(l.ms.mean()), flow_median=float(l.ms.median()), n_flows=int(len(l)),
    ev_n=int(len(e)), ev_mean=float(e.ms.mean()), ev_median=float(e.ms.median()),
    by_action={a: dict(flows=int((l.action_taken==a).sum()), events=int((e.action_taken==a).sum()),
                       ev_mean=float(e[e.action_taken==a].ms.mean()), ev_median=float(e[e.action_taken==a].ms.median()))
               for a in ['already_blocked','block_ip']},
    by_cat={c: dict(flows=int((l.attack_category==c).sum()), events=int((e.attack_category==c).sum()),
                    ev_mean=float(e[e.attack_category==c].ms.mean())) for c in sorted(l.attack_category.unique())},
    by_cloud={c: dict(flows=int((l.cloud==c).sum()), events=int((e.cloud==c).sum())) for c in sorted(l.cloud.unique())})
# session coverage
a = df[df.session_id.notna()]
def kind(g):
    s = set(g.action_taken)
    return 'direct' if s & {'block_ip','already_blocked'} else ('bnna_only' if 'blocked_no_new_alert' in s else 'none_only')
t = a.groupby(['cloud','attack_category','session_id']).apply(kind, include_groups=False).reset_index(name='k')
R['coverage'] = {f"{c}|{k}": int(v) for (c, k), v in t.groupby(['cloud','k']).size().items()}
R['coverage_by_cat'] = {f"{c}|{cat}|{k}": int(v) for (c, cat, k), v in t.groupby(['cloud','attack_category','k']).size().items()}
R['sessions_per_cloud'] = {c: int(v) for c, v in a.groupby('cloud').session_id.nunique().items()}
json.dump(R, open(out, 'w'), indent=1)
print(json.dumps(R, indent=1)[:6000])
