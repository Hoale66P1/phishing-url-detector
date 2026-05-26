import json
import os
import re
import sys
import time
from datetime import datetime

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)
from sklearn.model_selection import train_test_split

from detector.feature_extractor import URLFeatureExtractor

DATA_DIR = "data"
MODEL_DIR = "model"
DATASET_MAIN = os.path.join(DATA_DIR, "dataset.csv")
DATASET_VN_CRAWLED = os.path.join(DATA_DIR, "vn_benign_crawled.csv")
DATASET_VN_MANUAL = os.path.join(DATA_DIR, "vn_benign_manual.csv")
DATASET_COMBINED_OUT = os.path.join(DATA_DIR, "dataset_v3.csv")

MODEL_PATH = os.path.join(MODEL_DIR, "phishing_model.pkl")
FEATURE_NAMES_PATH = os.path.join(MODEL_DIR, "feature_names.pkl")
MODEL_PATH_V3 = os.path.join(MODEL_DIR, "phishing_model_v3.pkl")
FEATURE_NAMES_PATH_V3 = os.path.join(MODEL_DIR, "feature_names_v3.pkl")
METRICS_PATH = os.path.join(MODEL_DIR, "metrics_v3.json")

LABEL_MAP = {"benign": 0, "phishing": 1}

RE_VN = re.compile(r"\.vn(/|$|:|\?)", re.IGNORECASE)
RE_EDU_VN = re.compile(r"\.edu\.vn(/|$|:|\?)", re.IGNORECASE)
RE_GOV_VN = re.compile(r"\.gov\.vn(/|$|:|\?)", re.IGNORECASE)


def is_vn(url: str) -> bool:
    return bool(RE_VN.search(url))


def is_edu_or_gov_vn(url: str) -> bool:
    return bool(RE_EDU_VN.search(url) or RE_GOV_VN.search(url))


def compute_sample_weight(urls: pd.Series) -> np.ndarray:
    w = np.ones(len(urls), dtype=np.float64)
    for i, u in enumerate(urls):
        if is_edu_or_gov_vn(u):
            w[i] = 5.0
        elif is_vn(u):
            w[i] = 3.0
    return w


def load_main_dataset(path: str) -> pd.DataFrame:
    df = pd.read_csv(path)
    df = df[df["type"].isin(LABEL_MAP.keys())].copy()
    df["label"] = df["type"].map(LABEL_MAP)
    return df[["url", "label"]]


def load_vn_dataset(path: str) -> pd.DataFrame:
    df = pd.read_csv(path)
    df = df[["url", "label"]].copy()
    df["label"] = df["label"].astype(int)
    return df


def build_combined_dataset() -> pd.DataFrame:
    print("[1/7] Loading datasets...")
    main_df = load_main_dataset(DATASET_MAIN)
    print(f"      main:        {len(main_df):>7} rows  ({DATASET_MAIN})")

    if os.path.isfile(DATASET_VN_CRAWLED):
        crawled_df = load_vn_dataset(DATASET_VN_CRAWLED)
        print(f"      vn_crawled:  {len(crawled_df):>7} rows  ({DATASET_VN_CRAWLED})")
    else:
        crawled_df = pd.DataFrame(columns=["url", "label"])
        print(f"      vn_crawled:        0 rows  (missing — skipped)")

    if os.path.isfile(DATASET_VN_MANUAL):
        manual_df = load_vn_dataset(DATASET_VN_MANUAL)
        print(f"      vn_manual:   {len(manual_df):>7} rows  ({DATASET_VN_MANUAL})")
    else:
        manual_df = pd.DataFrame(columns=["url", "label"])
        print(f"      vn_manual:         0 rows  (missing — skipped)")

    combined = pd.concat([main_df, crawled_df, manual_df], ignore_index=True)
    before_dedup = len(combined)
    combined = combined.drop_duplicates(subset=["url"], keep="first").reset_index(drop=True)
    print(f"      combined:    {before_dedup:>7} rows pre-dedup -> {len(combined)} after dedup")

    combined.to_csv(DATASET_COMBINED_OUT, index=False)
    print(f"      saved combined dataset -> '{DATASET_COMBINED_OUT}'")

    total = len(combined)
    benign = int((combined["label"] == 0).sum())
    phishing = int((combined["label"] == 1).sum())
    vn_mask = combined["url"].apply(is_vn)
    edu_mask = combined["url"].str.contains(r"\.edu\.vn", case=False, na=False, regex=True)
    gov_mask = combined["url"].str.contains(r"\.gov\.vn", case=False, na=False, regex=True)
    print()
    print("      distribution:")
    print(f"        total:      {total}")
    print(f"        benign:     {benign}  ({benign / total * 100:.2f}%)")
    print(f"        phishing:   {phishing}  ({phishing / total * 100:.2f}%)")
    print(f"        .vn:        {int(vn_mask.sum())}  ({vn_mask.mean() * 100:.2f}%)")
    print(f"        .edu.vn:    {int(edu_mask.sum())}  ({edu_mask.mean() * 100:.4f}%)")
    print(f"        .gov.vn:    {int(gov_mask.sum())}  ({gov_mask.mean() * 100:.4f}%)")

    return combined


def evaluate_subset(name: str, y_true: np.ndarray, y_pred: np.ndarray) -> dict:
    if len(y_true) == 0:
        print(f"      {name}: no samples in this subset")
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
    print(
        f"      {name:<14} n={len(y_true):>6}  "
        f"(benign={n_benign}, phishing={n_phishing})"
    )
    print(
        f"                     accuracy={acc:.4f}  precision={prec:.4f}  "
        f"recall={rec:.4f}  f1={f1:.4f}"
    )
    print(f"                     confusion={cm}  benign_fp_rate={benign_fp_rate:.4f}")
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
    print("  PHISHING URL DETECTOR — TRAINING PIPELINE v3")
    print("=" * 70)
    print()

    df = build_combined_dataset()

    print("\n[2/7] Extracting features ...")
    t0 = time.time()
    extractor = URLFeatureExtractor()
    X = extractor.extract_batch(df["url"].tolist())
    y = df["label"].values
    print(f"      -> {X.shape[0]} rows × {X.shape[1]} features  ({time.time() - t0:.1f}s)")
    feature_names = list(X.columns)

    print("\n[3/7] Stratified split 80/20 (random_state=42) ...")
    urls = np.array(df["url"].astype(str).tolist(), dtype=object)
    X_train, X_test, y_train, y_test, urls_train, urls_test = train_test_split(
        X, y, urls, test_size=0.2, stratify=y, random_state=42,
    )
    print(f"      train: {X_train.shape[0]}   test: {X_test.shape[0]}")

    print("\n[4/7] Computing sample_weight (.vn ×3, .edu.vn/.gov.vn ×5) ...")
    sw_train = compute_sample_weight(pd.Series(urls_train))
    n5 = int((sw_train == 5.0).sum())
    n3 = int((sw_train == 3.0).sum())
    n1 = int((sw_train == 1.0).sum())
    print(f"      train rows: weight=5: {n5}   weight=3: {n3}   weight=1: {n1}")

    print("\n[5/7] Training RandomForest (n_est=200, max_depth=20, "
          "min_samples_leaf=5, class_weight=balanced) ...")
    t0 = time.time()
    model = RandomForestClassifier(
        n_estimators=200,
        max_depth=20,
        min_samples_leaf=5,
        class_weight="balanced",
        random_state=42,
        n_jobs=-1,
    )
    model.fit(X_train, y_train, sample_weight=sw_train)
    print(f"      training done in {time.time() - t0:.1f}s")

    print("\n[6/7] Evaluation ...")
    y_pred = model.predict(X_test)

    print()
    print("      --- OVERALL ---")
    overall = evaluate_subset("overall", y_test, y_pred)
    print()
    print("      --- PER-CLASS (classification_report) ---")
    cr = classification_report(
        y_test, y_pred, target_names=["benign", "phishing"], output_dict=True, zero_division=0,
    )
    print(classification_report(
        y_test, y_pred, target_names=["benign", "phishing"], zero_division=0,
    ))

    vn_mask = np.array([is_vn(u) for u in urls_test])
    print("      --- SUBSET: .vn only ---")
    sub_vn = evaluate_subset(".vn", y_test[vn_mask], y_pred[vn_mask])
    print()
    print("      --- SUBSET: non-.vn ---")
    sub_non_vn = evaluate_subset("non-.vn", y_test[~vn_mask], y_pred[~vn_mask])

    edu_gov_mask = np.array([is_edu_or_gov_vn(u) for u in urls_test])
    if edu_gov_mask.sum() > 0:
        print()
        print("      --- SUBSET: .edu.vn + .gov.vn only ---")
        sub_edu_gov = evaluate_subset("edu/gov.vn", y_test[edu_gov_mask], y_pred[edu_gov_mask])
    else:
        sub_edu_gov = {"count": 0}

    print("\n[7/7] Saving model and metrics ...")
    os.makedirs(MODEL_DIR, exist_ok=True)
    joblib.dump(model, MODEL_PATH)
    joblib.dump(model, MODEL_PATH_V3)
    joblib.dump(feature_names, FEATURE_NAMES_PATH)
    joblib.dump(feature_names, FEATURE_NAMES_PATH_V3)
    print(f"      model        -> '{MODEL_PATH}'  (default)")
    print(f"      model        -> '{MODEL_PATH_V3}'  (v3 archive)")
    print(f"      features     -> '{FEATURE_NAMES_PATH}', '{FEATURE_NAMES_PATH_V3}'")

    metrics = {
        "version": "v3",
        "trained_at": datetime.now().isoformat(timespec="seconds"),
        "dataset": {
            "total": int(len(df)),
            "benign": int((df["label"] == 0).sum()),
            "phishing": int((df["label"] == 1).sum()),
            "vn_count": int(df["url"].apply(is_vn).sum()),
            "edu_vn_count": int(df["url"].str.contains(r"\.edu\.vn", case=False, regex=True).sum()),
            "gov_vn_count": int(df["url"].str.contains(r"\.gov\.vn", case=False, regex=True).sum()),
        },
        "split": {"train": int(X_train.shape[0]), "test": int(X_test.shape[0])},
        "model": {
            "type": "RandomForestClassifier",
            "n_estimators": 200,
            "max_depth": 20,
            "min_samples_leaf": 5,
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
    print(f"      metrics      -> '{METRICS_PATH}'")

    print()
    print("=" * 70)
    print("  TRAINING v3 COMPLETE")
    print("=" * 70)
    return 0


if __name__ == "__main__":
    sys.exit(main())
