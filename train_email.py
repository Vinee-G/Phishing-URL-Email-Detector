"""Train the email TEXT model.
  python train_email.py                        # uses data/emails.csv (subject,body,label)
  python train_email.py --csv data/real.csv    # your data: columns text,label  (or subject,body,label)
"""
import argparse
import json
import joblib
import numpy as np
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import confusion_matrix, f1_score, precision_score, recall_score, roc_auc_score
from sklearn.model_selection import train_test_split
from sklearn.naive_bayes import MultinomialNB
from sklearn.pipeline import make_pipeline
from detector.email_features import clean_text

ap = argparse.ArgumentParser()
ap.add_argument("--csv", default="data/emails.csv")
args = ap.parse_args()

df = pd.read_csv(args.csv).dropna(subset=["label"])
if "text" not in df.columns:
    df["text"] = df["subject"].fillna("") + " " + df["body"].fillna("")
X = df["text"].fillna("").map(clean_text)
y = df["label"].astype(int)
Xtr, Xte, ytr, yte = train_test_split(X, y, test_size=0.25, random_state=42, stratify=y)
print(f"train {len(Xtr)} | test {len(Xte)}\n")

def vec():
    return TfidfVectorizer(ngram_range=(1, 2), min_df=2, sublinear_tf=True, stop_words="english")

models = {
    "LogisticRegression": make_pipeline(vec(), LogisticRegression(C=3, max_iter=2000, class_weight="balanced")),
    "NaiveBayes": make_pipeline(vec(), MultinomialNB(alpha=0.3)),
}
fitted = {}
print(f"{'model':20s} {'precision':>9s} {'recall':>7s} {'F1':>6s} {'AUC':>6s}  FP  FN")
res = {}
for name, m in models.items():
    m.fit(Xtr, ytr)
    p = m.predict_proba(Xte)[:, 1]
    pred = (p >= 0.5).astype(int)
    tn, fp, fn, tp = confusion_matrix(yte, pred).ravel()
    res[name] = {"precision": precision_score(yte, pred), "recall": recall_score(yte, pred),
                 "f1": f1_score(yte, pred), "auc": roc_auc_score(yte, p), "false_positives": int(fp), "false_negatives": int(fn)}
    fitted[name] = m
    r = res[name]
    print(f"{name:20s} {r['precision']:9.3f} {r['recall']:7.3f} {r['f1']:6.3f} {r['auc']:6.3f} {fp:3d} {fn:3d}")

# We ship Logistic Regression because its weights let us explain WHICH words raised the score
lr = fitted["LogisticRegression"]
words = np.array(lr[0].get_feature_names_out())
coef = lr[1].coef_[0]
print("\nWords pushing toward PHISHING:", ", ".join(words[np.argsort(-coef)[:10]]))
print("Words pushing toward LEGIT   :", ", ".join(words[np.argsort(coef)[:10]]))

joblib.dump(lr, "model/email_model.joblib")
json.dump({"results": res, "data": args.csv}, open("model/email_metrics.json", "w"), indent=2)
print("\nSaved model/email_model.joblib and model/email_metrics.json")
