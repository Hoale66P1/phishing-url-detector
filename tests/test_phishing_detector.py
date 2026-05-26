"""
================================================================================
TEST PLAN — Phishing URL Detector (Hybrid System)
================================================================================
Test Plan ID : TP-PUD-001
Project      : Phishing URL Detector (Whitelist + RandomForest v4 hybrid)
Author       : QA Engineering
Date         : 2026-05-26
Framework    : pytest

--------------------------------------------------------------------------------
SCOPE
--------------------------------------------------------------------------------
In scope:
  - URLFeatureExtractor: correctness of all 17 lexical features
  - Stage 1 validation behaviour of predict_url
  - Stage 2 whitelist matching + subdomain-attack prevention (security)
  - Stage 4 confidence-tier assignment (_assign_tier)
  - End-to-end hybrid pipeline (predict_url) routing
  - Regression guard for the historical Bare-URL Bias defect
  - Documented known limitations (typosquatting / content-based abuse)
  - Exploratory edge-case inputs

Out of scope:
  - Streamlit UI rendering, SQLite persistence, Plotly charts
  - Model training pipeline (train.py / train_v4.py)
  - Network crawling scripts (scripts/*.py)

--------------------------------------------------------------------------------
TEST ENVIRONMENT
--------------------------------------------------------------------------------
  - OS      : Windows 10/11, macOS, Ubuntu 20.04+
  - Python  : 3.11+
  - Deps    : pytest, scikit-learn, joblib, numpy, pandas
  - Model   : model/phishing_model_v4.pkl (+ feature_names_v4.pkl)
  - Run from: phishing-url-detector/  ->  pytest tests/ -v

--------------------------------------------------------------------------------
TEST DATA DEPENDENCIES
--------------------------------------------------------------------------------
  - data/whitelist_vn.txt  (108 pre-approved VN domains)
  - Trained model artefacts under model/ (optional; absence -> SKIP)

--------------------------------------------------------------------------------
RISK ASSESSMENT
--------------------------------------------------------------------------------
  - HIGH  : Whitelist subdomain-attack bypass would defeat Stage 2 entirely.
            Covered by TestWhitelistLogic.test_subdomain_attack_prevention.
  - HIGH  : Regression of Bare-URL Bias would re-break legitimate VN traffic.
            Covered by TestRegressionBareURLBias.
  - MED   : Threshold drift would mislabel confidence tiers in the UI.
            Covered by TestThresholdTier boundary cases.
  - LOW   : Feature-extraction errors degrade model input silently.
            Covered by TestFeatureExtractor.

================================================================================
EXPECTED RESULTS SUMMARY (with trained model present)
================================================================================
  - Total test cases : ~69
  - Expected PASS    : ~60
  - Expected XFAIL   : ~9   (6 unimplemented validation rules + 3 known limits)
  - Expected SKIP    : 0 locally / ~22 on CI without model
  - Expected FAIL    : 0
================================================================================
"""
import pytest

try:
    from app import predict_url, _is_whitelisted, _extract_root_domain, _assign_tier
    _APP_OK = True
    _APP_ERR = ""
except Exception as _exc:
    _APP_OK = False
    _APP_ERR = repr(_exc)
    predict_url = _is_whitelisted = _extract_root_domain = _assign_tier = None

requires_app = pytest.mark.skipif(not _APP_OK, reason=f"app module unavailable: {_APP_ERR}")

EXPECTED_FEATURE_KEYS = {
    "url_length", "domain_length", "path_length", "has_ip_address",
    "has_at_symbol", "has_double_slash", "has_hyphen_domain", "count_dots",
    "count_hyphens", "count_slash", "count_digits", "count_special_chars",
    "has_https", "has_shortening_service", "url_depth", "digit_ratio",
    "has_suspicious_words",
}


@pytest.mark.smoke
class TestFeatureExtractor:
    """Unit tests for URLFeatureExtractor — verifies all 17 lexical features."""

    def test_returns_exactly_17_features(self, extractor):
        """TC-FEAT-001: Extractor returns exactly 17 named features.
        Priority: High
        Precondition: Any well-formed URL
        Expected: dict of length 17 with the documented keys."""
        features = extractor.extract("https://example.com/path")
        assert len(features) == 17, f"Expected 17 features, got {len(features)}"
        assert set(features.keys()) == EXPECTED_FEATURE_KEYS

    def test_url_length_calculation(self, extractor):
        """TC-FEAT-002: url_length equals raw character count.
        Priority: Medium"""
        url = "https://example.com/path"
        assert extractor.extract(url)["url_length"] == len(url)

    def test_domain_length_calculation(self, extractor):
        """TC-FEAT-003: domain_length equals netloc length.
        Priority: Medium"""
        assert extractor.extract("https://shopee.vn")["domain_length"] == len("shopee.vn")

    def test_count_slash_with_path(self, extractor):
        """TC-FEAT-004: count_slash counts every '/' including scheme slashes.
        Priority: Medium"""
        assert extractor.extract("https://shopee.vn/products")["count_slash"] == 3

    def test_count_slash_bare_domain(self, extractor):
        """TC-FEAT-005: Bare domain has exactly two slashes (scheme only).
        Priority: High
        Note: Root-cause feature of the Bare-URL Bias defect (regression anchor)."""
        assert extractor.extract("https://shopee.vn")["count_slash"] == 2

    def test_count_dots_subdomain(self, extractor):
        """TC-FEAT-006: count_dots counts dots across the whole URL.
        Priority: Low"""
        assert extractor.extract("https://courses.uit.edu.vn")["count_dots"] == 3

    def test_has_ip_address_ipv4(self, extractor):
        """TC-FEAT-007: IPv4 host is flagged by has_ip_address.
        Priority: High"""
        assert extractor.extract("http://192.168.1.1/login")["has_ip_address"] == 1

    def test_has_https_detection(self, extractor):
        """TC-FEAT-008: has_https reflects the scheme.
        Priority: Medium"""
        assert extractor.extract("https://example.com")["has_https"] == 1
        assert extractor.extract("http://example.com")["has_https"] == 0

    def test_has_shortening_service_bitly(self, extractor):
        """TC-FEAT-009: Known URL shortener is flagged.
        Priority: High"""
        assert extractor.extract("https://bit.ly/3xKp9Lq")["has_shortening_service"] == 1

    def test_has_suspicious_words_login(self, extractor):
        """TC-FEAT-010: Suspicious keyword in URL is flagged.
        Priority: Medium"""
        assert extractor.extract("http://example.com/login")["has_suspicious_words"] == 1

    def test_digit_ratio_calculation(self, extractor):
        """TC-FEAT-011: digit_ratio equals digit-count divided by length.
        Priority: Low"""
        url = "http://a1234.com"
        expected = sum(c.isdigit() for c in url) / len(url)
        assert extractor.extract(url)["digit_ratio"] == pytest.approx(expected)

    def test_feature_types_all_numeric(self, extractor):
        """TC-FEAT-012: Every feature value is int or float (no None / str).
        Priority: High"""
        features = extractor.extract("https://example.com/a?b=1")
        for key, value in features.items():
            assert isinstance(value, (int, float)), f"{key} is {type(value)}"

    def test_empty_path_features(self, extractor):
        """TC-FEAT-013: Bare domain yields zero path_length and url_depth.
        Priority: Medium"""
        features = extractor.extract("https://example.com")
        assert features["path_length"] == 0
        assert features["url_depth"] == 0

    def test_unicode_url_handling(self, extractor):
        """TC-FEAT-014: Unicode URL is processed without raising.
        Priority: Medium"""
        features = extractor.extract("https://xn--mnchen-3ya.de/seite")
        assert len(features) == 17

    @pytest.mark.boundary
    def test_very_long_url(self, extractor):
        """TC-FEAT-015: URL beyond 2048 chars is handled.
        Priority: Medium
        Precondition: URL length > 2048
        Expected: 17 features returned, url_length > 2048."""
        url = "https://example.com/" + ("a" * 2100)
        features = extractor.extract(url)
        assert len(features) == 17
        assert features["url_length"] > 2048

    def test_special_characters_in_url(self, extractor):
        """TC-FEAT-016: Special characters increase count_special_chars.
        Priority: Low"""
        features = extractor.extract("https://example.com/?q=a&b=c%20d@e")
        assert features["count_special_chars"] > 0


@requires_app
class TestURLValidation:
    """Boundary and negative testing for Stage 1 (predict_url validation)."""

    def test_valid_https_url(self, whitelist):
        """TC-VAL-001: Verify HTTPS URL passes validation.
        Priority: High
        Precondition: Valid HTTPS URL with domain
        Expected: method is not INVALID."""
        assert predict_url(None, "https://shopee.vn", whitelist)["method"] != "INVALID"

    def test_valid_http_url(self, whitelist):
        """TC-VAL-002: Verify HTTP URL passes validation.
        Priority: Medium
        Expected: method is not INVALID."""
        assert predict_url(None, "http://shopee.vn", whitelist)["method"] != "INVALID"

    def test_empty_string_rejected(self, whitelist):
        """TC-VAL-003: Empty string is rejected at Stage 1.
        Priority: High
        Expected: method == INVALID."""
        assert predict_url(None, "", whitelist)["method"] == "INVALID"

    def test_whitespace_only_rejected(self, whitelist):
        """TC-VAL-004: Whitespace-only input is rejected.
        Priority: Medium
        Expected: method == INVALID."""
        assert predict_url(None, "   ", whitelist)["method"] == "INVALID"

    def test_none_input_rejected(self, whitelist):
        """TC-VAL-005: None input is rejected without raising.
        Priority: High
        Expected: method == INVALID."""
        assert predict_url(None, None, whitelist)["method"] == "INVALID"

    @pytest.mark.xfail(reason="Stage-1 does not yet reject scheme-less URLs", strict=False)
    def test_missing_scheme_rejected(self, detector, whitelist):
        """TC-VAL-006: Scheme-less URL should be rejected.
        Priority: Low
        Status: Known gap — validation layer not implemented."""
        assert predict_url(detector, "random-no-scheme-xyz.com", whitelist)["method"] == "INVALID"

    @pytest.mark.xfail(reason="Stage-1 does not yet reject ftp scheme", strict=False)
    def test_ftp_scheme_rejected(self, detector, whitelist):
        """TC-VAL-007: FTP scheme should be rejected.
        Priority: Low
        Status: Known gap — only http/https expected, but no enforcement."""
        assert predict_url(detector, "ftp://files.example.com/x", whitelist)["method"] == "INVALID"

    @pytest.mark.xfail(reason="Stage-1 does not yet reject localhost", strict=False)
    def test_localhost_rejected(self, detector, whitelist):
        """TC-VAL-008: localhost should be rejected.
        Priority: Low
        Status: Known gap."""
        assert predict_url(detector, "http://localhost/admin", whitelist)["method"] == "INVALID"

    @pytest.mark.xfail(reason="Stage-1 does not yet reject private IP ranges", strict=False)
    def test_private_ip_rejected(self, detector, whitelist):
        """TC-VAL-009: Private IP host should be rejected.
        Priority: Low
        Status: Known gap."""
        assert predict_url(detector, "http://10.0.0.1/x", whitelist)["method"] == "INVALID"

    @pytest.mark.xfail(reason="Stage-1 does not yet reject dot-less hostnames", strict=False)
    def test_no_dot_in_hostname_rejected(self, detector, whitelist):
        """TC-VAL-010: Hostname without a dot should be rejected.
        Priority: Low
        Status: Known gap."""
        assert predict_url(detector, "http://intranet/page", whitelist)["method"] == "INVALID"

    @pytest.mark.boundary
    @pytest.mark.xfail(reason="Stage-1 does not yet enforce a max length", strict=False)
    def test_url_too_long_rejected(self, detector, whitelist):
        """TC-VAL-011: URL longer than 2048 chars should be rejected.
        Priority: Low
        Status: Known gap — no length ceiling enforced."""
        long_url = "https://example.com/" + ("a" * 2100)
        assert predict_url(detector, long_url, whitelist)["method"] == "INVALID"


@requires_app
@pytest.mark.security
class TestWhitelistLogic:
    """Security tests for Stage 2 whitelist matching."""

    def test_exact_domain_match(self, whitelist):
        """TC-WL-001: Exact domain match is whitelisted.
        Priority: High"""
        matched, dom = _is_whitelisted("https://shopee.vn", whitelist)
        assert matched is True
        assert dom == "shopee.vn"

    def test_subdomain_match(self, whitelist):
        """TC-WL-002: Legitimate subdomain matches its registered root.
        Priority: High
        Expected: courses.uit.edu.vn matches uit.edu.vn."""
        matched, dom = _is_whitelisted("https://courses.uit.edu.vn", whitelist)
        assert matched is True
        assert dom == "uit.edu.vn"

    def test_subdomain_attack_prevention(self, whitelist):
        """TC-WL-003: Look-alike domain must NOT match a whitelisted brand.
        Priority: Critical
        Precondition: phishing-shopee.vn is a distinct registrable domain
        Expected: NOT whitelisted (no suffix bypass).
        Note: Highest-risk security case for the hybrid system."""
        matched, _ = _is_whitelisted("https://phishing-shopee.vn", whitelist)
        assert matched is False, "Look-alike domain bypassed the whitelist"

    def test_case_insensitive_match(self, whitelist):
        """TC-WL-004: Uppercase URL still matches whitelist.
        Priority: Medium"""
        matched, _ = _is_whitelisted("HTTPS://SHOPEE.VN", whitelist)
        assert matched is True

    def test_www_prefix_handling(self, whitelist):
        """TC-WL-005: www. prefix is stripped before matching.
        Priority: Medium"""
        matched, dom = _is_whitelisted("https://www.shopee.vn", whitelist)
        assert matched is True
        assert dom == "shopee.vn"

    def test_domain_not_in_whitelist(self, whitelist):
        """TC-WL-006: Unknown domain is not whitelisted.
        Priority: Medium"""
        matched, _ = _is_whitelisted("https://random-unknown-xyz123.com", whitelist)
        assert matched is False

    def test_empty_whitelist(self):
        """TC-WL-007: Empty whitelist matches nothing.
        Priority: Low"""
        matched, _ = _is_whitelisted("https://shopee.vn", set())
        assert matched is False

    def test_whitelist_file_loads_108_domains(self, whitelist):
        """TC-WL-008: Whitelist file loads the expected 108 domains.
        Priority: Medium"""
        assert len(whitelist) == 108

    def test_no_duplicate_in_whitelist(self, whitelist):
        """TC-WL-009: Whitelist set contains no duplicates by construction.
        Priority: Low"""
        assert len(whitelist) == len(set(whitelist))


@requires_app
class TestThresholdTier:
    """Logic tests for Stage 4 confidence-tier assignment (_assign_tier)."""

    def test_high_threshold_boundary(self):
        """TC-THR-001: Exactly 0.85 is HIGH.
        Priority: High"""
        assert _assign_tier(0.85) == "HIGH"

    def test_medium_threshold_boundary(self):
        """TC-THR-002: Exactly 0.55 is MEDIUM.
        Priority: High"""
        assert _assign_tier(0.55) == "MEDIUM"

    def test_high_above_boundary(self):
        """TC-THR-003: 0.86 is HIGH.
        Priority: Medium"""
        assert _assign_tier(0.86) == "HIGH"

    def test_medium_range(self):
        """TC-THR-004: 0.70 is MEDIUM.
        Priority: Medium"""
        assert _assign_tier(0.70) == "MEDIUM"

    def test_low_below_boundary(self):
        """TC-THR-005: 0.54 is LOW.
        Priority: Medium"""
        assert _assign_tier(0.54) == "LOW"

    def test_confidence_zero(self):
        """TC-THR-006: 0.0 is LOW.
        Priority: Low"""
        assert _assign_tier(0.0) == "LOW"

    def test_confidence_one(self):
        """TC-THR-007: 1.0 is HIGH.
        Priority: Low"""
        assert _assign_tier(1.0) == "HIGH"

    @pytest.mark.boundary
    def test_boundary_0_55_belongs_to_medium(self):
        """TC-THR-008: Lower MEDIUM boundary is inclusive.
        Priority: High"""
        assert _assign_tier(0.55) == "MEDIUM"
        assert _assign_tier(0.5499) == "LOW"

    @pytest.mark.boundary
    def test_boundary_0_85_belongs_to_high(self):
        """TC-THR-009: Lower HIGH boundary is inclusive.
        Priority: High"""
        assert _assign_tier(0.85) == "HIGH"
        assert _assign_tier(0.8499) == "MEDIUM"


@requires_app
@pytest.mark.integration
class TestHybridSystemIntegration:
    """End-to-end tests for the full predict_url hybrid pipeline."""

    def test_whitelist_url_returns_conf_1(self, detector, whitelist):
        """TC-INT-001: Whitelisted URL returns confidence 1.0.
        Priority: High"""
        result = predict_url(detector, "https://uit.edu.vn", whitelist)
        assert result["confidence"] == 1.0

    def test_whitelist_bypasses_ml(self, detector, whitelist):
        """TC-INT-002: Whitelisted URL is served by WHITELIST, not ML.
        Priority: High"""
        result = predict_url(detector, "https://shopee.vn", whitelist)
        assert result["method"] == "WHITELIST"

    def test_non_whitelist_uses_ml(self, detector, whitelist):
        """TC-INT-003: Unknown domain is routed to the ML model.
        Priority: High"""
        result = predict_url(detector, "https://random-unknown-xyz123abc.com", whitelist)
        assert result["method"] == "ML_MODEL"

    def test_obvious_phishing_not_marked_safe(self, detector, whitelist):
        """TC-INT-004: A brand-impersonation URL is not marked HIGH-confidence safe.
        Priority: High
        Note: v4 may not label it Phishing, but it must not be a confident benign."""
        result = predict_url(detector, "https://vietcombank-online.tk/login", whitelist)
        assert not (result["label"] == "Legitimate" and result["confidence_level"] == "HIGH")

    def test_legitimate_vn_url_benign(self, detector, whitelist):
        """TC-INT-005: Legitimate VN e-commerce URL is benign.
        Priority: High"""
        result = predict_url(detector, "https://shopee.vn/products", whitelist)
        assert result["is_phishing"] is False

    def test_shortening_service_flagged(self, detector, whitelist):
        """TC-INT-006: URL shortener is routed to ML and flagged phishing.
        Priority: Medium"""
        result = predict_url(detector, "https://bit.ly/3xKp9Lq", whitelist)
        assert result["method"] == "ML_MODEL"
        assert result["is_phishing"] is True


@requires_app
@pytest.mark.regression
class TestRegressionBareURLBias:
    """
    Regression Test Suite: Bare-URL Bias

    Bug History:
      - v1-v3: Bare-domain VN URLs (shopee.vn, vnexpress.net) were flagged
        phishing ~100% because the count_slash feature dominated importance
        and bare domains have the minimal slash count.
      - Root cause: training data lacked bare-domain benign examples.
      - Fixed in v4: augmented with Tranco list + ~43K bare-domain benign URLs.

    These tests assert the model does NOT regress: a bare VN domain must never
    be flagged as HIGH-confidence phishing. They probe the model directly
    (detector.predict) rather than the whitelist, since the defect lived in
    the model.
    """

    BARE_DOMAINS = [
        "https://shopee.vn",
        "https://vnexpress.net",
        "https://tiki.vn",
        "https://tuoitre.vn",
        "https://uit.edu.vn",
        "https://hcmut.edu.vn",
        "https://dantri.com.vn",
    ]

    @pytest.mark.parametrize("url", BARE_DOMAINS)
    def test_bare_domain_not_high_confidence_phishing(self, detector, url):
        """TC-REG-001..007: Bare VN domain is never HIGH-confidence phishing.
        Priority: Critical
        Expected: not (is_phishing and confidence >= 0.85)."""
        result = detector.predict(url)
        flagged_high = result["is_phishing"] and result["confidence"] >= 0.85
        assert not flagged_high, (
            f"Regression: {url} flagged phishing at conf={result['confidence']:.4f}"
        )


@requires_app
@pytest.mark.known_limitation
class TestKnownLimitations:
    """
    Test-as-documentation for accepted model blind spots.

    Each case is marked xfail: it encodes behaviour we WANT but the structural
    feature set of v4 cannot yet deliver. They are tracked here so a future
    model improvement is detected automatically (xpass -> investigate).
    """

    @pytest.mark.xfail(reason="v4 has no lexical/edit-distance feature for typosquats", strict=False)
    def test_typosquatting_shoppe_vn(self, detector):
        """TC-LIM-001: Typosquat 'shoppe.vn' should be flagged phishing.
        Priority: Medium
        Limitation: structural features miss single-char brand typos.
        Future fix: add Levenshtein-to-brand lexical feature."""
        assert detector.predict("https://shoppe.vn")["is_phishing"] is True

    @pytest.mark.xfail(reason="v4 cannot detect homoglyph substitution", strict=False)
    def test_typosquatting_faceb00k(self, detector):
        """TC-LIM-002: Homoglyph 'faceb00k.com' should be flagged phishing.
        Priority: Medium
        Limitation: digit-for-letter substitution not modelled.
        Future fix: homoglyph normalisation feature."""
        assert detector.predict("https://faceb00k.com")["is_phishing"] is True

    @pytest.mark.xfail(reason="content-based abuse is out of the URL-only scope", strict=False)
    def test_content_based_abuse_url(self, detector):
        """TC-LIM-003: A structurally clean but abusive URL should be flagged.
        Priority: Low
        Limitation: detector inspects URL structure only, not page content; a
        clean-looking gambling domain is classified benign.
        Future fix: integrate content/reputation signals."""
        assert detector.predict("https://onlinecasino.com")["is_phishing"] is True


@pytest.mark.smoke
class TestEdgeCases:
    """Exploratory and boundary inputs for the feature extractor."""

    def test_url_with_port_number(self, extractor):
        """TC-EDGE-001: Port number does not break extraction.
        Priority: Medium"""
        assert len(extractor.extract("https://example.com:8080/path")) == 17

    def test_url_with_query_params(self, extractor):
        """TC-EDGE-002: Query parameters increase special-char count.
        Priority: Low"""
        assert extractor.extract("https://x.com/s?q=1&p=2")["count_special_chars"] >= 3

    def test_url_with_fragment(self, extractor):
        """TC-EDGE-003: Fragment identifier is handled.
        Priority: Low"""
        assert len(extractor.extract("https://x.com/page#section")) == 17

    def test_url_with_authentication(self, extractor):
        """TC-EDGE-004: userinfo '@' is flagged by has_at_symbol.
        Priority: Medium"""
        assert extractor.extract("http://user:pass@host.com")["has_at_symbol"] == 1

    def test_internationalized_domain_name(self, extractor):
        """TC-EDGE-005: Raw IDN does not raise.
        Priority: Low"""
        assert len(extractor.extract("https://münchen.de/seite")) == 17

    def test_consecutive_dots_in_url(self, extractor):
        """TC-EDGE-006: Consecutive dots are still counted.
        Priority: Low"""
        assert extractor.extract("https://a..b.com")["count_dots"] >= 2

    def test_consecutive_slashes_in_path(self, extractor):
        """TC-EDGE-007: Double slash in path is flagged.
        Priority: Low"""
        assert extractor.extract("https://x.com//a//b")["has_double_slash"] == 1

    def test_url_with_encoded_characters(self, extractor):
        """TC-EDGE-008: Percent-encoded characters increase special-char count.
        Priority: Low"""
        assert extractor.extract("https://x.com/%20%3D")["count_special_chars"] >= 2


BUG_REPORT_TEMPLATE = """
## Bug Report Template

**Bug ID:** BUG-XXX
**Title:** [Component] Short description
**Severity:** Critical / Major / Minor / Trivial
**Priority:** P0 / P1 / P2 / P3
**Status:** Open / In Progress / Fixed / Verified
**Reporter:** [Name]
**Date:** YYYY-MM-DD

**Environment:**
- OS: Windows 10/11, macOS, Ubuntu 20.04+
- Python: 3.11+
- Model: phishing_model_v4.pkl

**Steps to Reproduce:**
1. ...
2. ...

**Expected Result:** ...
**Actual Result:** ...
**Evidence:** [Screenshot / Log / Test output]

**Root Cause Analysis:** ...
**Fix Verification:** [Test case ID that verifies the fix]

--------------------------------------------------------------------------------
## Worked Example (historical defect resolved in this project)

**Bug ID:** BUG-001
**Title:** [Model] Bare-domain VN URLs misclassified as phishing
**Severity:** Critical
**Priority:** P0
**Status:** Fixed / Verified

**Environment:**
- Python 3.11+, model phishing_model_v1..v3.pkl

**Steps to Reproduce:**
1. Load detector with model v3.
2. Call detector.predict("https://shopee.vn").

**Expected Result:** Legitimate with high confidence.
**Actual Result:** Phishing with confidence ~1.0 (10/10 VN bare domains failed).

**Root Cause Analysis:** count_slash dominated feature importance (~23%);
training set lacked bare-domain benign examples, so minimal-slash URLs
correlated with phishing.

**Fix Verification:** TestRegressionBareURLBias
(test_bare_domain_not_high_confidence_phishing) — parametrised over 7 VN
bare domains; all must satisfy NOT (is_phishing and confidence >= 0.85).
"""
