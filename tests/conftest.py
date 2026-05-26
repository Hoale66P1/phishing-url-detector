"""Shared pytest fixtures for the Phishing URL Detector test suite.

Adds the project root (phishing-url-detector/) to sys.path so that
`import app` and `from detector.* import *` resolve when pytest is invoked
from any working directory.
"""
import os
import sys

import pytest

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

WHITELIST_FILE = os.path.join(_ROOT, "data", "whitelist_vn.txt")


@pytest.fixture(scope="session")
def extractor():
    """Provide a shared URLFeatureExtractor instance.

    Purpose: feature-level unit tests do not require the trained model, so a
    single stateless extractor is reused across the session.
    """
    from detector.feature_extractor import URLFeatureExtractor
    return URLFeatureExtractor()


@pytest.fixture(scope="session")
def detector():
    """Provide a shared MaliciousURLDetector backed by the best available model.

    Purpose: integration / regression / known-limitation tests need real
    inference. If the .pkl files are absent (e.g. on CI without a trained
    model) the dependent tests are skipped rather than failed.
    """
    try:
        from detector.model import MaliciousURLDetector
        return MaliciousURLDetector()
    except FileNotFoundError as exc:
        pytest.skip(f"Trained model not available: {exc}")
    except Exception as exc:
        pytest.skip(f"Detector could not be constructed: {exc}")


@pytest.fixture(scope="session")
def whitelist():
    """Load the whitelist as a lowercase set directly from disk.

    Purpose: whitelist / hybrid tests need the same 108-domain set the app
    uses, parsed independently of Streamlit so no UI dependency is pulled in.
    """
    domains = set()
    if not os.path.isfile(WHITELIST_FILE):
        return domains
    with open(WHITELIST_FILE, encoding="utf-8") as fh:
        for line in fh:
            stripped = line.strip()
            if stripped and not stripped.startswith("#"):
                domains.add(stripped.lower())
    return domains


@pytest.fixture(scope="session")
def sample_urls():
    """Provide categorised URL samples used across multiple test suites.

    Categories:
      whitelisted    -> domains present in whitelist_vn.txt
      legitimate_vn  -> benign Vietnamese URLs (bare + path forms)
      phishing_like  -> URLs exhibiting phishing-style structure
      typosquat      -> brand-impersonation domains (known model blind spot)
      malformed      -> invalid / edge-case inputs
    """
    return {
        "whitelisted": [
            "https://shopee.vn",
            "https://uit.edu.vn",
            "https://vnexpress.net/news",
            "https://courses.uit.edu.vn",
        ],
        "legitimate_vn": [
            "https://shopee.vn/products",
            "https://tiki.vn/products/12345",
            "https://hcmut.edu.vn/admission",
        ],
        "phishing_like": [
            "https://bit.ly/3xKp9Lq",
            "http://192.168.1.1/secure/login/verify",
            "http://paypal-account-verify.tk/login",
        ],
        "typosquat": [
            "https://shoppe.vn",
            "https://faceb00k.com",
            "https://vietcombank-online.tk",
        ],
        "malformed": [
            "",
            "   ",
            "not a url",
        ],
    }
