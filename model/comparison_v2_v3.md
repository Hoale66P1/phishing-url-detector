# v2 vs v3 — VN Benign URL Comparison

Confidence threshold for 'correct': > 0.7


| # | URL | v2 pred | v2 conf | v3 pred | v3 conf | Status |
|---|---|---|---:|---|---:|---|
| 1 | `https://cafef.vn/du-lieu/hastc.chn` | PHISHING | 0.9876 | BENIGN | 0.6873 | ❌ STILL WRONG |
| 2 | `https://hcmut.edu.vn` | PHISHING | 1.0000 | PHISHING | 0.5096 | ❌ STILL WRONG |
| 3 | `https://www.citd.edu.vn` | PHISHING | 0.9980 | BENIGN | 0.5365 | ❌ STILL WRONG |
| 4 | `https://vnexpress.net` | PHISHING | 1.0000 | PHISHING | 0.9740 | ❌ STILL WRONG |
| 5 | `https://tuoitre.vn` | PHISHING | 1.0000 | PHISHING | 0.8826 | ❌ STILL WRONG |
| 6 | `https://shopee.vn` | PHISHING | 1.0000 | PHISHING | 0.7956 | ❌ STILL WRONG |
| 7 | `https://tiki.vn` | PHISHING | 1.0000 | PHISHING | 0.7091 | ❌ STILL WRONG |
| 8 | `https://thanhnien.vn` | PHISHING | 1.0000 | PHISHING | 0.9740 | ❌ STILL WRONG |
| 9 | `https://dantri.com.vn` | PHISHING | 1.0000 | PHISHING | 0.7225 | ❌ STILL WRONG |
| 10 | `https://uit.edu.vn` | PHISHING | 0.9983 | BENIGN | 0.6820 | ❌ STILL WRONG |

## Summary

- **v2 correct:** 0/10  (expected ~0/10)
- **v3 correct:** 0/10  (target ≥ 8/10)
- **Verdict:** **FAIL**

### URLs still failing

- `https://cafef.vn/du-lieu/hastc.chn` (STILL WRONG, v3 conf=0.6873)
- `https://hcmut.edu.vn` (STILL WRONG, v3 conf=0.5096)
- `https://www.citd.edu.vn` (STILL WRONG, v3 conf=0.5365)
- `https://vnexpress.net` (STILL WRONG, v3 conf=0.9740)
- `https://tuoitre.vn` (STILL WRONG, v3 conf=0.8826)
- `https://shopee.vn` (STILL WRONG, v3 conf=0.7956)
- `https://tiki.vn` (STILL WRONG, v3 conf=0.7091)
- `https://thanhnien.vn` (STILL WRONG, v3 conf=0.9740)
- `https://dantri.com.vn` (STILL WRONG, v3 conf=0.7225)
- `https://uit.edu.vn` (STILL WRONG, v3 conf=0.6820)

### Suggested next steps

- Add Tranco top-1M domains as benign reference (Step 3.5)
- Add VN-specific lexical features (TLD indicator, has_vn_subdomain)
- Inspect feature importance to see which features are flipping these URLs