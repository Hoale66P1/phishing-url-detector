import os
import sys
import time
import json

import joblib
import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
)
from sklearn.model_selection import train_test_split

from detector.feature_extractor import URLFeatureExtractor

DATASET_PATH = os.path.join("data", "dataset.csv")
MODEL_DIR = "model"
MODEL_PATH = os.path.join(MODEL_DIR, "phishing_model.pkl")
FEATURE_NAMES_PATH = os.path.join(MODEL_DIR, "feature_names.pkl")

LABEL_MAP = {"benign": 0, "phishing": 1}

stats = {}

print("[1] Loading dataset...")
df = pd.read_csv(DATASET_PATH)
total_raw = len(df)
print(f"    Raw rows: {total_raw}")

print(f"    Columns: {list(df.columns)}")
print(f"    Value counts for 'type': {df['type'].value_counts().to_dict()}")

df = df[df["type"].isin(LABEL_MAP.keys())].copy()
df["label"] = df["type"].map(LABEL_MAP)
total_filtered = len(df)
n_benign = int((df["label"] == 0).sum())
n_phishing = int((df["label"] == 1).sum())

stats["dataset"] = {
    "total_raw": total_raw,
    "total_filtered": total_filtered,
    "n_benign": n_benign,
    "n_phishing": n_phishing,
}
print(f"    Filtered: {total_filtered} (benign={n_benign}, phishing={n_phishing})")

print("[2] Extracting features...")
t0 = time.time()
extractor = URLFeatureExtractor()
X = extractor.extract_batch(df["url"].tolist())
y = df["label"].values
feature_time = time.time() - t0
print(f"    Features: {X.shape[1]}, Time: {feature_time:.2f}s")

feature_names = list(X.columns)

print("[3] Splitting 80/20...")
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, stratify=y, random_state=42
)
stats["split"] = {
    "train_size": int(X_train.shape[0]),
    "test_size": int(X_test.shape[0]),
    "test_ratio": 0.2,
}
print(f"    Train: {X_train.shape[0]}, Test: {X_test.shape[0]}")

print("[4] Training RandomForestClassifier(n_estimators=100, random_state=42)...")
t0 = time.time()
model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X_train, y_train)
train_time = time.time() - t0
stats["training"] = {
    "algorithm": "RandomForestClassifier",
    "n_estimators": 100,
    "random_state": 42,
    "training_time_seconds": train_time,
}
print(f"    Training time: {train_time:.4f}s")

print("[5] Evaluating...")
y_pred = model.predict(X_test)

acc = accuracy_score(y_test, y_pred)
prec = precision_score(y_test, y_pred)
rec = recall_score(y_test, y_pred)
f1 = f1_score(y_test, y_pred)

cm = confusion_matrix(y_test, y_pred)
tn, fp, fn, tp = cm.ravel()

stats["evaluation"] = {
    "accuracy": float(acc),
    "precision": float(prec),
    "recall": float(rec),
    "f1_score": float(f1),
}
stats["confusion_matrix"] = {
    "TP": int(tp),
    "TN": int(tn),
    "FP": int(fp),
    "FN": int(fn),
}

print(f"    Accuracy:  {acc}")
print(f"    Precision: {prec}")
print(f"    Recall:    {rec}")
print(f"    F1-Score:  {f1}")
print(f"    CM: TN={tn}, FP={fp}, FN={fn}, TP={tp}")

report = classification_report(y_test, y_pred, target_names=["benign", "phishing"])
print("\n" + report)

print("[6] Saving model...")
os.makedirs(MODEL_DIR, exist_ok=True)
joblib.dump(model, MODEL_PATH)
joblib.dump(feature_names, FEATURE_NAMES_PATH)

model_size_bytes = os.path.getsize(MODEL_PATH)
model_size_mb = model_size_bytes / (1024 * 1024)
stats["performance"] = {
    "model_file": MODEL_PATH,
    "model_size_bytes": model_size_bytes,
    "model_size_mb": model_size_mb,
}
print(f"    Model size: {model_size_bytes} bytes ({model_size_mb:.2f} MB)")

print("[7] Measuring inference time...")
_ = model.predict(X_test.iloc[:1])

test_urls = df["url"].tolist()[:100]
t0 = time.time()
for url in test_urls:
    feats = extractor.extract(url)
    feat_df = pd.DataFrame([feats], columns=feature_names)
    _ = model.predict(feat_df)
total_inf_time = time.time() - t0
avg_inf_time = total_inf_time / len(test_urls)

stats["performance"]["avg_inference_time_seconds"] = avg_inf_time
stats["performance"]["avg_inference_time_ms"] = avg_inf_time * 1000
print(f"    Avg inference per URL: {avg_inf_time*1000:.4f} ms")

print("\n========== STATS JSON ==========")
print(json.dumps(stats, indent=2, ensure_ascii=False))
print("========== END STATS ==========")
