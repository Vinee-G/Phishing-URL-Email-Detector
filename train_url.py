"""Train the URL model.
  python train_url.py                       # uses data/urls.csv (synthetic by default)
  python train_url.py --csv data/real.csv   # your real data: columns url,label  (1 = phishing)
"""
import argparse
import json
import joblib
import pandas as pd
from sklearn.ensemble import GradientBoostingClassifier, RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import confusion_matrix, f1_score, precision_score, recall_score, roc_auc_score
from sklearn.model_selection import GroupShuffleSplit
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler
from detector.url_features import FEATURE_NAMES, extract, registered_domain

ap = argparse.ArgumentParser()
ap.add_argument("--csv", default="data/urls.csv")
args = ap.parse_args()

df = pd.read_csv(args.csv).dropna(subset=["url", "label"])
X = pd.DataFrame([extract(u) for u in df["url"]])[FEATURE_NAMES]
y = df["label"].astype(int)
groups = df["url"].map(registered_domain)

# Split by DOMAIN so the same site never appears in both train and test (prevents memorizing)
gss = GroupShuffleSplit(n_splits=1, test_size=0.25, random_state=42)
tr, te = next(gss.split(X, y, groups))
Xtr, Xte, ytr, yte = X.iloc[tr], X.iloc[te], y.iloc[tr], y.iloc[te]
print(f"train {len(Xtr)} | test {len(Xte)} | phishing share {y.mean():.0%}\n")

models = {
    "LogisticRegression": make_pipeline(StandardScaler(), LogisticRegression(max_iter=2000, class_weight="balanced")),
    "RandomForest": RandomForestClassifier(n_estimators=200, max_depth=12, class_weight="balanced", random_state=42, n_jobs=-1),
    "GradientBoosting": GradientBoostingClassifier(random_state=42),
}
results, fitted = {}, {}
print(f"{'model':20s} {'precision':>9s} {'recall':>7s} {'F1':>6s} {'AUC':>6s}  FP  FN")
for name, m in models.items():
    m.fit(Xtr, ytr)
    p = m.predict_proba(Xte)[:, 1]
    pred = (p >= 0.5).astype(int)
    tn, fp, fn, tp = confusion_matrix(yte, pred).ravel()
    r = {"precision": precision_score(yte, pred), "recall": recall_score(yte, pred),
         "f1": f1_score(yte, pred), "auc": roc_auc_score(yte, p), "false_positives": int(fp), "false_negatives": int(fn)}
    results[name], fitted[name] = r, m
    print(f"{name:20s} {r['precision']:9.3f} {r['recall']:7.3f} {r['f1']:6.3f} {r['auc']:6.3f} {fp:3d} {fn:3d}")

best = max(results, key=lambda k: results[k]["f1"])
model = fitted[best]
print(f"\nBest model by F1: {best}")
if hasattr(model, "feature_importances_"):
    imp = sorted(zip(FEATURE_NAMES, model.feature_importances_), key=lambda t: -t[1])[:8]
    print("Top features:", ", ".join(f"{n} ({v:.2f})" for n, v in imp))

joblib.dump({"model": model, "features": FEATURE_NAMES, "name": best}, "model/url_model.joblib")
json.dump({"best": best, "results": results, "data": args.csv}, open("model/url_metrics.json", "w"), indent=2)
print("Saved model/url_model.joblib and model/url_metrics.json")
