import sys
import os
import unittest

import pandas as pd

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from detector.feature_extractor import URLFeatureExtractor


class TestURLFeatureExtractor(unittest.TestCase):

    EXPECTED_KEYS = [
        "url_length", "domain_length", "path_length",
        "has_ip_address", "has_at_symbol", "has_double_slash",
        "has_hyphen_domain", "count_dots", "count_hyphens",
        "count_slash", "count_digits", "count_special_chars",
        "has_https", "has_shortening_service", "url_depth",
        "digit_ratio", "has_suspicious_words",
    ]

    def setUp(self):
        self.extractor = URLFeatureExtractor()

    def test_extract_returns_dict(self):
        result = self.extractor.extract("https://example.com")
        self.assertIsInstance(result, dict)

    def test_extract_has_all_keys(self):
        result = self.extractor.extract("https://example.com/path")
        for key in self.EXPECTED_KEYS:
            self.assertIn(key, result, f"Missing key: {key}")
        self.assertEqual(len(result), 17)

    def test_url_length_correct(self):
        url = "https://example.com/test"
        result = self.extractor.extract(url)
        self.assertEqual(result["url_length"], len(url))

    def test_has_https_true(self):
        result = self.extractor.extract("https://secure.example.com")
        self.assertEqual(result["has_https"], 1)

    def test_has_https_false(self):
        result = self.extractor.extract("http://example.com")
        self.assertEqual(result["has_https"], 0)

    def test_has_at_symbol_true(self):
        result = self.extractor.extract("http://user@example.com")
        self.assertEqual(result["has_at_symbol"], 1)

    def test_has_at_symbol_false(self):
        result = self.extractor.extract("http://example.com")
        self.assertEqual(result["has_at_symbol"], 0)

    def test_has_ip_address_true(self):
        result = self.extractor.extract("http://192.168.1.1/page")
        self.assertEqual(result["has_ip_address"], 1)

    def test_has_ip_address_false(self):
        result = self.extractor.extract("http://example.com/page")
        self.assertEqual(result["has_ip_address"], 0)

    def test_invalid_url_returns_zeros(self):
        result = self.extractor.extract("")
        self.assertIsInstance(result, dict)
        self.assertEqual(len(result), 17)
        for key, value in result.items():
            self.assertEqual(value, 0 if key != "digit_ratio" else 0.0,
                             f"Key '{key}' should be 0 for empty URL")

    def test_suspicious_words_detected(self):
        result = self.extractor.extract("http://example.com/login")
        self.assertEqual(result["has_suspicious_words"], 1)

    def test_extract_batch_returns_dataframe(self):
        urls = ["https://google.com", "http://bit.ly/abc", "http://example.com"]
        result = self.extractor.extract_batch(urls)
        self.assertIsInstance(result, pd.DataFrame)
        self.assertEqual(len(result), 3)
        self.assertEqual(len(result.columns), 17)


if __name__ == "__main__":
    unittest.main()
