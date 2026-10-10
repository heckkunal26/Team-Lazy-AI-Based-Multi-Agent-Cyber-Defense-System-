"""Train on the REAL NSL-KDD dataset and report honest metrics on the official KDDTest+ split.
Models: (1) supervised RandomForest -> normal/DoS/Probe/R2L/U2R   (2) IsolationForest on normal-only flows for unseen/zero-day anomalies."""
import json, sys, time
from pathlib import Path
import joblib, numpy as np, pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OrdinalEncoder

D = Path("data"); M = Path("models"); M.mkdir(exist_ok=True)
COLS = ["duration","protocol_type","service","flag","src_bytes","dst_bytes","land","wrong_fragment","urgent","hot","num_failed_logins","logged_in",
 "num_compromised","root_shell","su_attempted","num_root","num_file_creations","num_shells","num_access_files","num_outbound_cmds","is_host_login","is_guest_login",
 "count","srv_count","serror_rate","srv_serror_rate","rerror_rate","srv_rerror_rate","same_srv_rate","diff_srv_rate","srv_diff_host_rate","dst_host_count",
 "dst_host_srv_count","dst_host_same_srv_rate","dst_host_diff_srv_rate","dst_host_same_src_port_rate","dst_host_srv_diff_host_rate","dst_host_serror_rate",
 "dst_host_srv_serror_rate","dst_host_rerror_rate","dst_host_srv_rerror_rate"]
CAT = ["protocol_type", "service", "flag"]
FAMILY = {"normal": "normal",
 **{a: "DoS" for a in "back land neptune pod smurf teardrop apache2 udpstorm processtable worm mailbomb".split()},
 **{a: "Probe" for a in "satan ipsweep nmap portsweep mscan saint".split()},
 **{a: "R2L" for a in "guess_passwd ftp_write imap phf multihop warezmaster warezclient spy xlock xsnoop snmpguess snmpgetattack httptunnel sendmail named".split()},
 **{a: "U2R" for a in "buffer_overflow loadmodule rootkit perl sqlattack xterm ps".split()}}

def load(name):
    df = pd.read_csv(D / name, header=None, names=COLS + ["label", "difficulty"])
    df["family"] = df["label"].map(FAMILY).fillna("R2L")
    return df

def build():
    pre = ColumnTransformer([("c", OrdinalEncoder(handle_unknown="use_encoded_value", unknown_value=-1), CAT)], remainder="passthrough")
    return Pipeline([("pre", pre), ("rf", RandomForestClassifier(n_estimators=200, n_jobs=-1, random_state=7, class_weight="balanced_subsample", min_samples_leaf=2))])

if __name__ == "__main__":
    tr, te = load("KDDTrain+.txt"), load("KDDTest+.txt"); t0 = time.time()
    clf = build().fit(tr[COLS], tr["family"])
    pred = clf.predict(te[COLS]); proba = clf.predict_proba(te[COLS])
    classes = list(clf.classes_)
    p_att = 1 - proba[:, classes.index("normal")]
    y_bin = (te["family"] != "normal").values
    # Isolation Forest on normal-only training flows (catches attacks the classifier never saw)
    X_norm = clf.named_steps["pre"].transform(tr.loc[tr.family == "normal", COLS])
    iso = IsolationForest(n_estimators=200, random_state=7, n_jobs=-1).fit(X_norm)
    iso_s = -iso.score_samples(clf.named_steps["pre"].transform(te[COLS]))
    thr = float(np.percentile(-iso.score_samples(X_norm), 99))
    ens = (p_att >= .5) | (iso_s > thr)
    def bin_metrics(flag):
        tp = int((flag & y_bin).sum()); fp = int((flag & ~y_bin).sum()); fn = int((~flag & y_bin).sum()); tn = int((~flag & ~y_bin).sum())
        return dict(tp=tp, fp=fp, fn=fn, tn=tn, precision=round(tp / max(tp + fp, 1), 4), recall=round(tp / max(tp + fn, 1), 4), accuracy=round((tp + tn) / len(flag), 4))
    rep = classification_report(te["family"], pred, output_dict=True, zero_division=0)
    metrics = dict(dataset="NSL-KDD (KDDTrain+ 125,973 flows / KDDTest+ 22,544 flows)", train_seconds=round(time.time() - t0, 1),
        multiclass_accuracy=round(float((pred == te["family"]).mean()), 4), per_class={k: {m: round(v[m], 3) for m in ("precision", "recall", "support")} for k, v in rep.items() if k in classes},
        binary_classifier_only=bin_metrics(p_att >= .5), binary_ensemble_with_isolation_forest=bin_metrics(ens),
        confusion_matrix=dict(labels=classes, matrix=confusion_matrix(te["family"], pred, labels=classes).tolist()), iso_threshold=thr,
        note="KDDTest+ deliberately contains attack types absent from training, so scores are lower than random-split numbers. These are honest held-out results.")
    names = CAT + [c for c in COLS if c not in CAT]; Xn = np.asarray(X_norm, dtype=float)
    joblib.dump(dict(clf=clf, iso=iso, iso_thr=thr, classes=classes, names=names, mu=Xn.mean(0), sd=np.maximum(Xn.std(0), 1e-3)), M / "model.joblib", compress=3)
    json.dump(metrics, open(M / "metrics.json", "w"), indent=1); print(json.dumps(metrics, indent=1))
