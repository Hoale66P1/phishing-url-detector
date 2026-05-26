import sys
import os
import numpy as np
import pandas as pd
from detector.model import MaliciousURLDetector
from detector.feature_extractor import URLFeatureExtractor

V2_MODEL_PATH = os.path.join("model", "phishing_model_v2.pkl")
V2_FEATURES_PATH = os.path.join("model", "feature_names_v2.pkl")
V3_MODEL_PATH = os.path.join("model", "phishing_model_v3.pkl")
V3_FEATURES_PATH = os.path.join("model", "feature_names_v3.pkl")
V4_MODEL_PATH = os.path.join("model", "phishing_model_v4.pkl")
V4_FEATURES_PATH = os.path.join("model", "feature_names_v4.pkl")
COMPARISON_OUT = os.path.join("model", "comparison_v2_v3.md")
COMPARISON_V4_OUT = os.path.join("model", "comparison_v2_v3_v4.md")
CONF_THRESHOLD = 0.7

VN_TEST_URLS = [
    "https://cafef.vn/du-lieu/hastc.chn",
    "https://hcmut.edu.vn",
    "https://www.citd.edu.vn",
    "https://vnexpress.net",
    "https://tuoitre.vn",
    "https://shopee.vn",
    "https://tiki.vn",
    "https://thanhnien.vn",
    "https://dantri.com.vn",
    "https://uit.edu.vn",
]

SEPARATOR = "=" * 90
THIN_SEP = "-" * 90


def part1_model_predictions():
    print(SEPARATOR)
    print("  PART 1: MODEL PREDICTION DIAGNOSIS")
    print(SEPARATOR)

    detector = MaliciousURLDetector()
    extractor = URLFeatureExtractor()

    test_urls = [
        "https://cafef.vn/du-lieu/hastc.chn",
        "https://hcmut.edu.vn",
        "https://www.citd.edu.vn",
        "https://vnexpress.net",
        "https://tuoitre.vn",
        "https://shopee.vn",
        "https://tiki.vn",
        "https://thanhnien.vn",
        "https://dantri.com.vn",
        "https://uit.edu.vn",
    ]

    key_features = [
        "url_length", "domain_length", "path_length",
        "count_hyphens", "count_dots", "count_slash",
        "count_digits", "digit_ratio", "has_https",
        "has_hyphen_domain", "count_special_chars",
        "has_suspicious_words", "url_depth",
    ]

    print()
    print(f"{'URL':<42} {'LABEL':<12} {'CONF':>6}")
    print(THIN_SEP)

    all_details = []

    for url in test_urls:
        result = detector.predict(url)
        features = extractor.extract(url)
        all_details.append((url, result, features))

        label_str = result["label"]
        conf_str = f"{result['confidence']:.4f}"
        marker = " <<< FALSE POSITIVE" if result["is_phishing"] else ""
        print(f"{url:<42} {label_str:<12} {conf_str:>6}{marker}")

    print()
    print(SEPARATOR)
    print("  DETAILED FEATURE BREAKDOWN")
    print(SEPARATOR)

    for url, result, features in all_details:
        print()
        print(f"  URL: {url}")
        print(f"  Prediction: {result['label']} (confidence={result['confidence']:.4f})")
        print(f"  {'Feature':<28} {'Value':>10}")
        print(f"  {'-'*28} {'-'*10}")
        for fname in key_features:
            val = features.get(fname, "N/A")
            if isinstance(val, float):
                print(f"  {fname:<28} {val:>10.4f}")
            else:
                print(f"  {fname:<28} {val:>10}")

    print()
    print(SEPARATOR)
    print("  FEATURE IMPORTANCE (from trained model)")
    print(SEPARATOR)

    model = detector.model
    feature_names = detector.feature_names

    if hasattr(model, "feature_importances_"):
        importances = model.feature_importances_
        sorted_idx = np.argsort(importances)[::-1]
        print()
        print(f"  {'Rank':<6} {'Feature':<30} {'Importance':>12}")
        print(f"  {'-'*6} {'-'*30} {'-'*12}")
        for rank, idx in enumerate(sorted_idx, 1):
            print(f"  {rank:<6} {feature_names[idx]:<30} {importances[idx]:>12.6f}")
    else:
        print("  Model does not expose feature_importances_.")


def part2_dataset_analysis():
    print()
    print(SEPARATOR)
    print("  PART 2: DATASET VN-DOMAIN COVERAGE ANALYSIS")
    print(SEPARATOR)

    dataset_path = "data/dataset.csv"
    if not os.path.isfile(dataset_path):
        print(f"  [ERROR] '{dataset_path}' not found.")
        return

    df = pd.read_csv(dataset_path)
    total = len(df)
    print(f"  Total samples: {total}")

    benign_df = df[df["type"] == "benign"]
    phishing_df = df[df["type"] == "phishing"]
    print(f"  Benign: {len(benign_df)}  |  Phishing: {len(phishing_df)}")

    tld_groups = {
        ".vn": r"\.vn(/|$)",
        ".com.vn": r"\.com\.vn(/|$)",
        ".edu.vn": r"\.edu\.vn(/|$)",
        ".gov.vn": r"\.gov\.vn(/|$)",
    }

    print()
    print(f"  {'TLD Group':<14} {'Total':>8} {'% Total':>9} {'Benign':>8} {'Phishing':>10}")
    print(f"  {'-'*14} {'-'*8} {'-'*9} {'-'*8} {'-'*10}")

    for tld_name, pattern in tld_groups.items():
        mask = df["url"].str.contains(pattern, case=False, na=False)
        count = mask.sum()
        pct = (count / total) * 100

        benign_count = (mask & (df["type"] == "benign")).sum()
        phishing_count = (mask & (df["type"] == "phishing")).sum()

        print(f"  {tld_name:<14} {count:>8} {pct:>8.4f}% {benign_count:>8} {phishing_count:>10}")

    print()
    print(THIN_SEP)
    print("  CONCLUSION:")
    vn_mask = df["url"].str.contains(r"\.vn(/|$)", case=False, na=False)
    vn_count = vn_mask.sum()
    vn_pct = (vn_count / total) * 100
    if vn_pct < 1.0:
        print(f"  .vn domains make up only {vn_pct:.4f}% of the dataset ({vn_count}/{total}).")
        print("  -> The model has very little exposure to Vietnamese URLs.")
        print("  -> This is a likely cause of false positives on .vn domains.")
    else:
        print(f"  .vn domains represent {vn_pct:.2f}% of the dataset.")
    print(THIN_SEP)


def test_url_variants():
    print()
    print(SEPARATOR)
    print("  PART 3.5A: URL VARIANT TEST (verify bare-domain hypothesis)")
    print(SEPARATOR)

    if not os.path.isfile(V3_MODEL_PATH) or not os.path.isfile(V3_FEATURES_PATH):
        print(f"  [ERROR] v3 model files not found: '{V3_MODEL_PATH}'")
        return

    v3 = MaliciousURLDetector(model_path=V3_MODEL_PATH, feature_names_path=V3_FEATURES_PATH)

    domains = ["shopee.vn", "hcmut.edu.vn", "vnexpress.net"]
    variants_template = [
        ("bare",          "https://{d}"),
        ("bare+slash",    "https://{d}/"),
        ("www",           "https://www.{d}"),
        ("path-fake",     "https://{d}/products"),
        ("path-long",     "https://{d}/sale-page"),
    ]

    results: dict[str, list[dict]] = {}

    for d in domains:
        rows = []
        for label, tmpl in variants_template:
            url = tmpl.format(d=d)
            r = v3.predict(url)
            rows.append({
                "variant": label,
                "url": url,
                "pred": "BENIGN" if not r["is_phishing"] else "PHISHING",
                "conf": r["confidence"],
                "passes": (not r["is_phishing"]) and r["confidence"] > CONF_THRESHOLD,
            })
        results[d] = rows

    for d, rows in results.items():
        print()
        print(f"  Domain: {d}")
        print(f"  {'Variant':<14} {'URL':<42} {'v3 pred':<10} {'v3 conf':>8}  pass?")
        print(f"  {'-'*14} {'-'*42} {'-'*10} {'-'*8}  -----")
        for r in rows:
            mark = "YES" if r["passes"] else "no"
            print(
                f"  {r['variant']:<14} {r['url']:<42} {r['pred']:<10} "
                f"{r['conf']:>8.4f}  {mark}"
            )

    bare_passes = sum(1 for d in domains for r in results[d] if r["variant"].startswith("bare") and r["passes"])
    bare_total = sum(1 for d in domains for r in results[d] if r["variant"].startswith("bare"))
    nonbare_passes = sum(1 for d in domains for r in results[d] if not r["variant"].startswith("bare") and r["passes"])
    nonbare_total = sum(1 for d in domains for r in results[d] if not r["variant"].startswith("bare"))

    print()
    print(f"  Bare-domain variants passing:    {bare_passes}/{bare_total}")
    print(f"  Non-bare variants  passing:      {nonbare_passes}/{nonbare_total}")

    if nonbare_passes > bare_passes:
        print("  -> HYPOTHESIS CONFIRMED: non-bare variants pass more often than bare.")
    elif nonbare_passes == bare_passes == 0:
        print("  -> HYPOTHESIS REJECTED: all variants still fail; root cause is broader.")
    else:
        print("  -> Inconclusive: similar pass rates across both forms.")


def part3_v2_vs_v3_comparison():
    print()
    print(SEPARATOR)
    print("  PART 3: v2 vs v3 COMPARISON ON 10 VN BENIGN URLs")
    print(SEPARATOR)

    for required in (V2_MODEL_PATH, V2_FEATURES_PATH, V3_MODEL_PATH, V3_FEATURES_PATH):
        if not os.path.isfile(required):
            print(f"  [ERROR] Missing required model file: '{required}'")
            return

    v2 = MaliciousURLDetector(model_path=V2_MODEL_PATH, feature_names_path=V2_FEATURES_PATH)
    v3 = MaliciousURLDetector(model_path=V3_MODEL_PATH, feature_names_path=V3_FEATURES_PATH)

    rows = []
    v2_correct_count = 0
    v3_correct_count = 0

    for i, url in enumerate(VN_TEST_URLS, 1):
        r2 = v2.predict(url)
        r3 = v3.predict(url)

        v2_benign = not r2["is_phishing"]
        v3_benign = not r3["is_phishing"]
        v2_conf = r2["confidence"]
        v3_conf = r3["confidence"]

        v2_correct = v2_benign and v2_conf > CONF_THRESHOLD
        v3_correct = v3_benign and v3_conf > CONF_THRESHOLD

        if v2_correct:
            v2_correct_count += 1
        if v3_correct:
            v3_correct_count += 1

        if v2_correct and v3_correct:
            status = "OK"
        elif (not v2_correct) and v3_correct:
            status = "FIXED"
        elif v2_correct and (not v3_correct):
            status = "REGRESSION"
        else:
            status = "STILL WRONG"

        rows.append({
            "n": i,
            "url": url,
            "v2_pred": "BENIGN" if v2_benign else "PHISHING",
            "v2_conf": v2_conf,
            "v3_pred": "BENIGN" if v3_benign else "PHISHING",
            "v3_conf": v3_conf,
            "status": status,
        })

    status_marker = {
        "OK": "[OK]",
        "FIXED": "[FIXED]",
        "REGRESSION": "[REGRESSION]",
        "STILL WRONG": "[STILL WRONG]",
    }

    print()
    header = (
        f"  {'#':<3} {'URL':<40} {'v2 pred':<10} {'v2 conf':>8}  "
        f"{'v3 pred':<10} {'v3 conf':>8}  {'Status':<14}"
    )
    print(header)
    print("  " + "-" * (len(header) - 2))
    for r in rows:
        print(
            f"  {r['n']:<3} {r['url']:<40} {r['v2_pred']:<10} {r['v2_conf']:>8.4f}  "
            f"{r['v3_pred']:<10} {r['v3_conf']:>8.4f}  {status_marker[r['status']]:<14}"
        )

    print()
    print(f"  v2 correct: {v2_correct_count}/10  (expected ~0/10)")
    print(f"  v3 correct: {v3_correct_count}/10  (target >= 8/10)")
    verdict = "PASS" if v3_correct_count >= 8 else "FAIL"
    print(f"  VERDICT: {verdict}")

    status_icon = {
        "OK": "✅ OK",
        "FIXED": "✅ FIXED",
        "REGRESSION": "❌ REGRESSION",
        "STILL WRONG": "❌ STILL WRONG",
    }

    lines = []
    lines.append("# v2 vs v3 — VN Benign URL Comparison\n")
    lines.append(f"Confidence threshold for 'correct': > {CONF_THRESHOLD}\n")
    lines.append("")
    lines.append("| # | URL | v2 pred | v2 conf | v3 pred | v3 conf | Status |")
    lines.append("|---|---|---|---:|---|---:|---|")
    for r in rows:
        lines.append(
            f"| {r['n']} | `{r['url']}` | {r['v2_pred']} | {r['v2_conf']:.4f} | "
            f"{r['v3_pred']} | {r['v3_conf']:.4f} | {status_icon[r['status']]} |"
        )
    lines.append("")
    lines.append("## Summary")
    lines.append("")
    lines.append(f"- **v2 correct:** {v2_correct_count}/10  (expected ~0/10)")
    lines.append(f"- **v3 correct:** {v3_correct_count}/10  (target ≥ 8/10)")
    lines.append(f"- **Verdict:** **{verdict}**")
    lines.append("")
    if verdict == "FAIL":
        still_wrong = [r for r in rows if r["status"] in ("STILL WRONG", "REGRESSION")]
        if still_wrong:
            lines.append("### URLs still failing")
            lines.append("")
            for r in still_wrong:
                lines.append(
                    f"- `{r['url']}` ({r['status']}, v3 conf={r['v3_conf']:.4f})"
                )
            lines.append("")
        lines.append("### Suggested next steps")
        lines.append("")
        lines.append("- Add Tranco top-1M domains as benign reference (Step 3.5)")
        lines.append("- Add VN-specific lexical features (TLD indicator, has_vn_subdomain)")
        lines.append("- Inspect feature importance to see which features are flipping these URLs")

    os.makedirs(os.path.dirname(COMPARISON_OUT), exist_ok=True)
    with open(COMPARISON_OUT, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    print(f"\n  Markdown report saved -> '{COMPARISON_OUT}'")


PATH_FAKE_URLS = [
    "https://shopee.vn/products",
    "https://tiki.vn/products/12345",
    "https://hcmut.edu.vn/admission",
    "https://vnexpress.net/news",
    "https://lazada.vn/category/electronics",
]


def part4_v2_v3_v4_comparison():
    print()
    print(SEPARATOR)
    print("  PART 4: v2 vs v3 vs v4 — 10 BARE + 5 PATH-FAKE URLs")
    print(SEPARATOR)

    for required in (
        V2_MODEL_PATH, V2_FEATURES_PATH,
        V3_MODEL_PATH, V3_FEATURES_PATH,
        V4_MODEL_PATH, V4_FEATURES_PATH,
    ):
        if not os.path.isfile(required):
            print(f"  [ERROR] Missing model file: '{required}'")
            return

    v2 = MaliciousURLDetector(model_path=V2_MODEL_PATH, feature_names_path=V2_FEATURES_PATH)
    v3 = MaliciousURLDetector(model_path=V3_MODEL_PATH, feature_names_path=V3_FEATURES_PATH)
    v4 = MaliciousURLDetector(model_path=V4_MODEL_PATH, feature_names_path=V4_FEATURES_PATH)

    def predict(model, url):
        r = model.predict(url)
        return {
            "pred": "BENIGN" if not r["is_phishing"] else "PHISHING",
            "conf": r["confidence"],
            "correct": (not r["is_phishing"]) and r["confidence"] > CONF_THRESHOLD,
        }

    sections = [
        ("bare-domain (Step-4 set)", VN_TEST_URLS),
        ("path-fake (new set)", PATH_FAKE_URLS),
    ]

    rows: list[dict] = []
    counts = {"v2": [0, 0], "v3": [0, 0], "v4": [0, 0]}

    for section_idx, (section_name, urls) in enumerate(sections):
        for i, url in enumerate(urls, 1):
            r2 = predict(v2, url)
            r3 = predict(v3, url)
            r4 = predict(v4, url)

            if section_idx == 0:
                if r2["correct"]: counts["v2"][0] += 1
                if r3["correct"]: counts["v3"][0] += 1
                if r4["correct"]: counts["v4"][0] += 1
            else:
                if r2["correct"]: counts["v2"][1] += 1
                if r3["correct"]: counts["v3"][1] += 1
                if r4["correct"]: counts["v4"][1] += 1

            if r3["correct"] and r4["correct"]:
                status = "OK"
            elif (not r3["correct"]) and r4["correct"]:
                status = "FIXED"
            elif r3["correct"] and (not r4["correct"]):
                status = "REGRESSION"
            else:
                status = "STILL WRONG"

            rows.append({
                "section": section_name, "n": i, "url": url,
                "v2_pred": r2["pred"], "v2_conf": r2["conf"],
                "v3_pred": r3["pred"], "v3_conf": r3["conf"],
                "v4_pred": r4["pred"], "v4_conf": r4["conf"],
                "status": status,
            })

    icon = {
        "OK": "[OK]", "FIXED": "[FIXED]",
        "REGRESSION": "[REGRESSION]", "STILL WRONG": "[STILL WRONG]",
    }
    print(f"\n  {'#':<3} {'URL':<42} "
          f"{'v2':<10}{'conf':>7}  {'v3':<10}{'conf':>7}  {'v4':<10}{'conf':>7}  status")
    print("  " + "-" * 110)
    current_section = None
    for r in rows:
        if r["section"] != current_section:
            current_section = r["section"]
            print(f"  --- {current_section} ---")
        print(
            f"  {r['n']:<3} {r['url']:<42} "
            f"{r['v2_pred']:<10}{r['v2_conf']:>7.4f}  "
            f"{r['v3_pred']:<10}{r['v3_conf']:>7.4f}  "
            f"{r['v4_pred']:<10}{r['v4_conf']:>7.4f}  "
            f"{icon[r['status']]}"
        )

    print()
    print(f"  v2 correct: {counts['v2'][0]}/10 bare  +  {counts['v2'][1]}/5 path-fake")
    print(f"  v3 correct: {counts['v3'][0]}/10 bare  +  {counts['v3'][1]}/5 path-fake")
    print(f"  v4 correct: {counts['v4'][0]}/10 bare  +  {counts['v4'][1]}/5 path-fake")
    bare_pass = counts["v4"][0] >= 9
    fake_pass = counts["v4"][1] >= 4
    verdict = "PASS" if (bare_pass and fake_pass) else "FAIL"
    print(f"  VERDICT: {verdict}  "
          f"(target: bare >= 9/10  AND  path-fake >= 4/5)")

    md_icon = {
        "OK": "✅ OK", "FIXED": "✅ FIXED",
        "REGRESSION": "❌ REGRESSION", "STILL WRONG": "❌ STILL WRONG",
    }
    lines = []
    lines.append("# v2 vs v3 vs v4 — VN URL Comparison")
    lines.append("")
    lines.append(f"Confidence threshold for 'correct': > {CONF_THRESHOLD}  ")
    lines.append("Status compares **v4 vs v3** on each URL: FIXED = v3 wrong → v4 correct, "
                 "OK = both correct, REGRESSION = v3 correct → v4 wrong, STILL WRONG = both wrong.")
    lines.append("")
    lines.append("## Bare-domain set (Step-4 original 10)")
    lines.append("")
    lines.append("| # | URL | v2 pred | v2 conf | v3 pred | v3 conf | v4 pred | v4 conf | Status |")
    lines.append("|---|---|---|---:|---|---:|---|---:|---|")
    for r in [x for x in rows if x["section"] == sections[0][0]]:
        lines.append(
            f"| {r['n']} | `{r['url']}` | "
            f"{r['v2_pred']} | {r['v2_conf']:.4f} | "
            f"{r['v3_pred']} | {r['v3_conf']:.4f} | "
            f"{r['v4_pred']} | {r['v4_conf']:.4f} | "
            f"{md_icon[r['status']]} |"
        )
    lines.append("")
    lines.append("## Path-fake set (new 5 — generalisation check)")
    lines.append("")
    lines.append("| # | URL | v2 pred | v2 conf | v3 pred | v3 conf | v4 pred | v4 conf | Status |")
    lines.append("|---|---|---|---:|---|---:|---|---:|---|")
    for r in [x for x in rows if x["section"] == sections[1][0]]:
        lines.append(
            f"| {r['n']} | `{r['url']}` | "
            f"{r['v2_pred']} | {r['v2_conf']:.4f} | "
            f"{r['v3_pred']} | {r['v3_conf']:.4f} | "
            f"{r['v4_pred']} | {r['v4_conf']:.4f} | "
            f"{md_icon[r['status']]} |"
        )
    lines.append("")
    lines.append("## Summary")
    lines.append("")
    lines.append("| Model | Bare-domain (10) | Path-fake (5) |")
    lines.append("|---|---:|---:|")
    lines.append(f"| v2 | {counts['v2'][0]}/10 | {counts['v2'][1]}/5 |")
    lines.append(f"| v3 | {counts['v3'][0]}/10 | {counts['v3'][1]}/5 |")
    lines.append(f"| **v4** | **{counts['v4'][0]}/10** | **{counts['v4'][1]}/5** |")
    lines.append("")
    lines.append(f"**Target:** ≥9/10 bare-domain  AND  ≥4/5 path-fake")
    lines.append(f"**Verdict:** **{verdict}**")
    lines.append("")
    if verdict == "FAIL":
        wrong = [r for r in rows if r["status"] in ("STILL WRONG", "REGRESSION")]
        if wrong:
            lines.append("### Failing URLs")
            lines.append("")
            for r in wrong:
                lines.append(
                    f"- `{r['url']}` ({r['status']}, v4 conf={r['v4_conf']:.4f})"
                )

    os.makedirs(os.path.dirname(COMPARISON_V4_OUT), exist_ok=True)
    with open(COMPARISON_V4_OUT, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    print(f"\n  Markdown report saved -> '{COMPARISON_V4_OUT}'")

    return {"verdict": verdict, "counts": counts, "rows": rows}


if __name__ == "__main__":
    part1_model_predictions()
    part2_dataset_analysis()
    part3_v2_vs_v3_comparison()
    part4_v2_v3_v4_comparison()
