# v2 vs v3 vs v4 — VN URL Comparison

Confidence threshold for 'correct': > 0.7  
Status compares **v4 vs v3** on each URL: FIXED = v3 wrong → v4 correct, OK = both correct, REGRESSION = v3 correct → v4 wrong, STILL WRONG = both wrong.

## Bare-domain set (Step-4 original 10)

| # | URL | v2 pred | v2 conf | v3 pred | v3 conf | v4 pred | v4 conf | Status |
|---|---|---|---:|---|---:|---|---:|---|
| 1 | `https://cafef.vn/du-lieu/hastc.chn` | PHISHING | 0.9876 | BENIGN | 0.6873 | BENIGN | 0.6746 | ❌ STILL WRONG |
| 2 | `https://hcmut.edu.vn` | PHISHING | 1.0000 | PHISHING | 0.5096 | BENIGN | 0.9986 | ✅ FIXED |
| 3 | `https://www.citd.edu.vn` | PHISHING | 0.9980 | BENIGN | 0.5365 | BENIGN | 0.9979 | ✅ FIXED |
| 4 | `https://vnexpress.net` | PHISHING | 1.0000 | PHISHING | 0.9740 | BENIGN | 0.9715 | ✅ FIXED |
| 5 | `https://tuoitre.vn` | PHISHING | 1.0000 | PHISHING | 0.8826 | BENIGN | 0.9931 | ✅ FIXED |
| 6 | `https://shopee.vn` | PHISHING | 1.0000 | PHISHING | 0.7956 | BENIGN | 0.9935 | ✅ FIXED |
| 7 | `https://tiki.vn` | PHISHING | 1.0000 | PHISHING | 0.7091 | BENIGN | 0.9974 | ✅ FIXED |
| 8 | `https://thanhnien.vn` | PHISHING | 1.0000 | PHISHING | 0.9740 | BENIGN | 0.9839 | ✅ FIXED |
| 9 | `https://dantri.com.vn` | PHISHING | 1.0000 | PHISHING | 0.7225 | BENIGN | 0.9950 | ✅ FIXED |
| 10 | `https://uit.edu.vn` | PHISHING | 0.9983 | BENIGN | 0.6820 | BENIGN | 0.9985 | ✅ FIXED |

## Path-fake set (new 5 — generalisation check)

| # | URL | v2 pred | v2 conf | v3 pred | v3 conf | v4 pred | v4 conf | Status |
|---|---|---|---:|---|---:|---|---:|---|
| 1 | `https://shopee.vn/products` | PHISHING | 1.0000 | PHISHING | 0.7831 | BENIGN | 0.9287 | ✅ FIXED |
| 2 | `https://tiki.vn/products/12345` | PHISHING | 0.9550 | PHISHING | 0.8658 | BENIGN | 0.5585 | ❌ STILL WRONG |
| 3 | `https://hcmut.edu.vn/admission` | PHISHING | 1.0000 | PHISHING | 0.6302 | BENIGN | 0.5388 | ❌ STILL WRONG |
| 4 | `https://vnexpress.net/news` | PHISHING | 1.0000 | PHISHING | 0.8783 | PHISHING | 0.6547 | ❌ STILL WRONG |
| 5 | `https://lazada.vn/category/electronics` | PHISHING | 1.0000 | PHISHING | 0.7683 | BENIGN | 0.9400 | ✅ FIXED |

## Summary

| Model | Bare-domain (10) | Path-fake (5) |
|---|---:|---:|
| v2 | 0/10 | 0/5 |
| v3 | 0/10 | 0/5 |
| **v4** | **9/10** | **2/5** |

**Target:** ≥9/10 bare-domain  AND  ≥4/5 path-fake
**Verdict:** **FAIL**

### Failing URLs

- `https://cafef.vn/du-lieu/hastc.chn` (STILL WRONG, v4 conf=0.6746)
- `https://tiki.vn/products/12345` (STILL WRONG, v4 conf=0.5585)
- `https://hcmut.edu.vn/admission` (STILL WRONG, v4 conf=0.5388)
- `https://vnexpress.net/news` (STILL WRONG, v4 conf=0.6547)