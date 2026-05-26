import sys
import os
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from detector.model import MaliciousURLDetector


class TestMaliciousURLDetector(unittest.TestCase):

    def setUp(self):
        self.detector = MaliciousURLDetector()
        self.test_url = "https://example.com/login?user=123"

    def test_model_loads_successfully(self):
        detector = MaliciousURLDetector()
        self.assertIsNotNone(detector.model)
        self.assertIsNotNone(detector.feature_names)
        self.assertIsNotNone(detector.extractor)

    def test_predict_returns_dict(self):
        result = self.detector.predict(self.test_url)
        self.assertIsInstance(result, dict)

    def test_predict_has_required_keys(self):
        result = self.detector.predict(self.test_url)
        required_keys = ["url", "label", "confidence", "is_phishing"]
        for key in required_keys:
            self.assertIn(key, result, f"Missing key: {key}")

    def test_confidence_in_valid_range(self):
        result = self.detector.predict(self.test_url)
        self.assertGreaterEqual(result["confidence"], 0.0)
        self.assertLessEqual(result["confidence"], 1.0)

    def test_predict_label_is_valid(self):
        result = self.detector.predict(self.test_url)
        self.assertIn(result["label"], ["Phishing", "Legitimate"])

    def test_is_phishing_is_bool(self):
        result = self.detector.predict(self.test_url)
        self.assertIsInstance(result["is_phishing"], bool)

    def test_get_feature_details_returns_dict(self):
        result = self.detector.get_feature_details(self.test_url)
        self.assertIsInstance(result, dict)
        self.assertEqual(len(result), 17)

    def test_model_file_not_found_raises_error(self):
        with self.assertRaises(FileNotFoundError):
            MaliciousURLDetector(model_path="nonexistent/model.pkl")


if __name__ == "__main__":
    unittest.main()
