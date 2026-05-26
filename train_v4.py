import json
import os
import sys
import time
from datetime import datetime

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score, classification_report, confusion_matrix, f1_score,
    precision_score, recall_score,
)
from sklearn.model_selection import train_test_split

from detector.feature_extractor import URLFeatureExtractor
from train import (
    is_vn, is_edu_or_gov_vn, compute_sample_weight,
)

DATA_DIR = "data"
MODEL_DIR = "model"
DATASET_V3 = os.path.join(DATA_DIR, "dataset_v3.csv")
ADDITIONAL_SOURCES = [
    os.path.join(DATA_DIR, "tranco_vn.csv"),
    os.path.join(DATA_DIR, "tranco_global_top10k.csv"),
    os.path.join(DATA_DIR, "vn_ecommerce_paths.csv"),
]
DATASET_V4_OUT = os.path.join(DATA_DIR, "dataset_v4.csv")
MODEL_PATH = os.path.join(MODEL_DIR, "phishing_model.pkl")
FEATURE_NAMES_PATH = os.path.join(MODEL_DIR, "feature_names.pkl")
MODEL_PATH_V4 = os.path.join(MODEL_DIR, "phishing_model_v4.pkl")
FEATURE_NAMES_PATH_V4 = os.path.join(MODEL_DIR, "feature_names_v4.pkl")
METRICS_PATH = os.path.join(MODEL_DIR, "metrics_v4.json")
METRICS_V3_PATH = os.path.join(MODEL_DIR, "metrics_v3.json")


def evaluate_subset(name: str, y_true: np.ndarray, y_pred: np.ndarray) -> dict:
    if len(y_true) == 0:
        return {"count": 0}
    acc = accuracy_score(y_true, y_pred)
    prec = precision_score(y_true, y_pred, zero_division=0)
    rec = recall_score(y_true, y_pred, zero_division=0)
    f1 = f1_score(y_true, y_pred, zero_division=0)
    cm = confusion_matrix(y_true, y_pred, labels=[0, 1]).tolist()
    n_benign = int((y_true == 0).sum())
    n_phishing = int((y_true == 1).sum())
    benign_fp_rate = 0.0
    if n_benign > 0:
        benign_fp_rate = float(((y_pred == 1) & (y_true == 0)).sum()) / n_benign
    return {
        "count": int(len(y_true)),
        "n_benign": n_benign,
        "n_phishing": n_phishing,
        "accuracy": float(acc),
        "precision": float(prec),
        "recall": float(rec),
        "f1": float(f1),
        "confusion_matrix": cm,
        "benign_false_positive_rate": benign_fp_rate,
    }


def main() -> int:
    print("=" * 70)
    print("  PHISHING URL DETECTOR — TRAINING PIPELINE v4")
    print("=" * 70)

    print("\n[1/7] Loading dataset_v3 + extra sources ...")
    df_v3 = pd.read_csv(DATASET_V3)[["url", "label"]]
    print(f"      dataset_v3:  {len(df_v3):>7} rows")

    extras = []
    for path in ADDITIONAL_SOURCES:
        if os.path.isfile(path):
            d = pd.read_csv(path)[["url", "label"]]
            d["label"] = d["label"].astype(int)
            extras.append(d)
            print(f"      {os.path.basename(path):<32} {len(d):>7} rows")
        else:
            print(f"      [WARN] missing: {path}")

    combined = pd.concat([df_v3] + extras, ignore_index=True)
    before = len(combined)
    combined = combined.drop_duplicates(subset=["url"], keep="first").reset_index(drop=True)
    print(f"      combined:    {before:>7} pre-dedup -> {len(combined)} after dedup")

    combined.to_csv(DATASET_V4_OUT, index=False)
    print(f"      saved -> '{DATASET_V4_OUT}'")

    total = len(combined)
    benign = int((combined["label"] == 0).sum())
    phishing = int((combined["label"] == 1).sum())
    vn_mask = combined["url"].apply(is_vn)
    edu_mask = combined["url"].str.contains(r"\.edu\.vn", case=False, regex=True, na=False)
    gov_mask = combined["url"].str.contains(r"\.gov\.vn", case=False, regex=True, na=False)
    print("\n      distribution:")
    print(f"        total:     {total}")
    print(f"        benign:    {benign}  ({benign/total*100:.2f}%)")
    print(f"        phishing:  {phishing}  ({phishing/total*100:.2f}%)")
    print(f"        .vn:       {int(vn_mask.sum())}  ({vn_mask.mean()*100:.2f}%)")
    print(f"        .edu.vn:   {int(edu_mask.sum())}  ({edu_mask.mean()*100:.4f}%)")
    print(f"        .gov.vn:   {int(gov_mask.sum())}  ({gov_mask.mean()*100:.4f}%)")

    print("\n[2/7] Extracting features ...")
    t0 = time.time()
    extractor = URLFeatureExtractor()
    X = extractor.extract_batch(combined["url"].tolist())
    y = combined["label"].values
    print(f"      -> {X.shape[0]} rows × {X.shape[1]} features  ({time.time()-t0:.1f}s)")
    feature_names = list(X.columns)

    print("\n[3/7] Stratified split 80/20 (random_state=42) ...")
    urls = np.array(combined["url"].astype(str).tolist(), dtype=object)
    X_train, X_test, y_train, y_test, urls_train, urls_test = train_test_split(
        X, y, urls, test_size=0.2, stratify=y, random_state=42,
    )
    print(f"      train: {X_train.shape[0]}   test: {X_test.shape[0]}")

    print("\n[4/7] Computing sample_weight ...")
    sw_train = compute_sample_weight(pd.Series(urls_train))
    n5 = int((sw_train == 5.0).sum())
    n3 = int((sw_train == 3.0).sum())
    n1 = int((sw_train == 1.0).sum())
    print(f"      weight=5: {n5}   weight=3: {n3}   weight=1: {n1}")

    print("\n[5/7] Training RandomForest (same config as v3) ...")
    t0 = time.time()
    model = RandomForestClassifier(
        n_estimators=200, max_depth=20, min_samples_leaf=5,
        class_weight="balanced", random_state=42, n_jobs=-1,
    )
    model.fit(X_train, y_train, sample_weight=sw_train)
    print(f"      done in {time.time()-t0:.1f}s")

    print("\n[6/7] Evaluation ...")
    y_pred = model.predict(X_test)

    overall = evaluate_subset("overall", y_test, y_pred)
    vn_mask_t = np.array([is_vn(u) for u in urls_test])
    sub_vn = evaluate_subset(".vn", y_test[vn_mask_t], y_pred[vn_mask_t])
    sub_non_vn = evaluate_subset("non-.vn", y_test[~vn_mask_t], y_pred[~vn_mask_t])
    edu_gov_mask = np.array([is_edu_or_gov_vn(u) for u in urls_test])
    sub_edu_gov = evaluate_subset("edu/gov.vn", y_test[edu_gov_mask], y_pred[edu_gov_mask])

    cr = classification_report(
        y_test, y_pred, target_names=["benign", "phishing"],
        output_dict=True, zero_division=0,
    )

    print("\n[7/7] Saving model + metrics ...")
    os.makedirs(MODEL_DIR, exist_ok=True)
    joblib.dump(model, MODEL_PATH)
    joblib.dump(model, MODEL_PATH_V4)
    joblib.dump(feature_names, FEATURE_NAMES_PATH)
    joblib.dump(feature_names, FEATURE_NAMES_PATH_V4)
    print(f"      model -> '{MODEL_PATH}', '{MODEL_PATH_V4}'")

    metrics = {
        "version": "v4",
        "trained_at": datetime.now().isoformat(timespec="seconds"),
        "dataset": {
            "total": int(len(combined)),
            "benign": benign,
            "phishing": phishing,
            "vn_count": int(vn_mask.sum()),
            "edu_vn_count": int(edu_mask.sum()),
            "gov_vn_count": int(gov_mask.sum()),
        },
        "split": {"train": int(X_train.shape[0]), "test": int(X_test.shape[0])},
        "model": {
            "type": "RandomForestClassifier",
            "n_estimators": 200, "max_depth": 20, "min_samples_leaf": 5,
            "class_weight": "balanced",
            "sample_weight_rule": "vn=3, edu/gov.vn=5, other=1",
        },
        "overall": overall,
        "per_class": cr,
        "subset_vn": sub_vn,
        "subset_non_vn": sub_non_vn,
        "subset_edu_gov_vn": sub_edu_gov,
    }
    with open(METRICS_PATH, "w", encoding="utf-8") as f:
        json.dump(metrics, f, indent=2, ensure_ascii=False)
    print(f"      metrics -> '{METRICS_PATH}'")

    print()
    print("=" * 70)
    print("  v3 vs v4 COMPARISON (5 subsets)")
    print("=" * 70)
    try:
        with open(METRICS_V3_PATH, "r", encoding="utf-8") as f:
            v3m = json.load(f)
    except Exception:
        v3m = None

    def fmt(m: dict, key: str) -> str:
        if not m or m.get("count", 0) == 0:
            return "  N/A"
        return f"{m.get(key, 0):.4f}" if isinstance(m.get(key), (int, float)) else "  N/A"

    rows = [
        ("overall", overall, (v3m or {}).get("overall", {})),
        (".vn only", sub_vn, (v3m or {}).get("subset_vn", {})),
        ("edu/gov.vn", sub_edu_gov, (v3m or {}).get("subset_edu_gov_vn", {})),
        ("non-.vn", sub_non_vn, (v3m or {}).get("subset_non_vn", {})),
        ("phishing-class", {"accuracy": cr["phishing"]["precision"],
                            "precision": cr["phishing"]["precision"],
                            "recall": cr["phishing"]["recall"],
                            "f1": cr["phishing"]["f1-score"],
                            "benign_false_positive_rate": 0.0,
                            "count": int(cr["phishing"]["support"])},
         (v3m or {}).get("per_class", {}).get("phishing", {})),
    ]

    print()
    print(f"  {'Subset':<14} {'n':>7}  "
          f"{'v3 acc':>8} {'v4 acc':>8}  "
          f"{'v3 fp':>8} {'v4 fp':>8}  "
          f"{'v3 f1':>8} {'v4 f1':>8}")
    print(f"  {'-'*14} {'-'*7}  {'-'*8} {'-'*8}  {'-'*8} {'-'*8}  {'-'*8} {'-'*8}")
    for name, v4m, v3sub in rows:
        n = v4m.get("count", 0)
        if name == "phishing-class":
            v3_acc = v3sub.get("precision", 0) if v3sub else None
            v4_acc = v4m["accuracy"]
            v3_f1 = v3sub.get("f1-score", 0) if v3sub else None
            v4_f1 = v4m["f1"]
            v3_fp = None
            v4_fp = None
        else:
            v3_acc = v3sub.get("accuracy") if v3sub else None
            v4_acc = v4m.get("accuracy", 0)
            v3_f1 = v3sub.get("f1") if v3sub else None
            v4_f1 = v4m.get("f1", 0)
            v3_fp = v3sub.get("benign_false_positive_rate") if v3sub else None
            v4_fp = v4m.get("benign_false_positive_rate", 0)
        def s(v):
            return f"{v:.4f}" if isinstance(v, (int, float)) else "    N/A"
        print(
            f"  {name:<14} {n:>7}  "
            f"{s(v3_acc):>8} {s(v4_acc):>8}  "
            f"{s(v3_fp):>8} {s(v4_fp):>8}  "
            f"{s(v3_f1):>8} {s(v4_f1):>8}"
        )

    print()
    print("=" * 70)
    print("  TRAINING v4 COMPLETE")
    print("=" * 70)
    return 0


if __name__ == "__main__":
    sys.exit(main())
