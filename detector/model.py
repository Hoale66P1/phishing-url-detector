import os

import joblib
import numpy as np
import pandas as pd

from detector.feature_extractor import URLFeatureExtractor

MODEL_DIR = "model"
DEFAULT_MODEL_PATH = os.path.join(MODEL_DIR, "phishing_model.pkl")
DEFAULT_FEATURE_NAMES_PATH = os.path.join(MODEL_DIR, "feature_names.pkl")

_VERSION_CHAIN = ["v4", "v3", "v2", None]


def _resolve_best_model() -> tuple[str, str, str]:
    for ver in _VERSION_CHAIN:
        if ver is None:
            mp = DEFAULT_MODEL_PATH
            fp = DEFAULT_FEATURE_NAMES_PATH
            label = "default"
        else:
            mp = os.path.join(MODEL_DIR, f"phishing_model_{ver}.pkl")
            fp = os.path.join(MODEL_DIR, f"feature_names_{ver}.pkl")
            label = ver
        if os.path.isfile(mp) and os.path.isfile(fp):
            return mp, fp, label
    return DEFAULT_MODEL_PATH, DEFAULT_FEATURE_NAMES_PATH, "missing"


class MaliciousURLDetector:

    def __init__(
        self,
        model_path: str | None = None,
        feature_names_path: str | None = None,
    ):
        if model_path is None or feature_names_path is None:
            resolved_mp, resolved_fp, version_label = _resolve_best_model()
            model_path = model_path or resolved_mp
            feature_names_path = feature_names_path or resolved_fp
            print(f"Loaded model: {version_label} (with hybrid system)")
            self.model_version = version_label
        else:
            self.model_version = "explicit"

        if not os.path.isfile(model_path):
            raise FileNotFoundError(
                f"Model file not found: '{model_path}'. "
                "Please run 'python train.py' (or 'python train_v4.py') first."
            )

        if not os.path.isfile(feature_names_path):
            raise FileNotFoundError(
                f"Feature names file not found: '{feature_names_path}'. "
                "Please run 'python train.py' (or 'python train_v4.py') first."
            )

        try:
            self.model = joblib.load(model_path)
            self.feature_names = joblib.load(feature_names_path)
        except Exception as e:
            raise RuntimeError(
                f"Failed to load model files: {e}. "
                "The .pkl files may be corrupted. Please retrain the model."
            ) from e

        self.extractor = URLFeatureExtractor()

    def predict(self, url: str) -> dict:
        features = self.extractor.extract(url)
        feature_df = pd.DataFrame([features], columns=self.feature_names)
        prediction = self.model.predict(feature_df)[0]
        probabilities = self.model.predict_proba(feature_df)[0]
        is_phishing = bool(prediction == 1)
        label = "Phishing" if is_phishing else "Legitimate"
        confidence = float(np.max(probabilities))
        return {
            "url": url,
            "label": label,
            "confidence": confidence,
            "is_phishing": is_phishing,
        }

    def get_feature_details(self, url: str) -> dict:
        return self.extractor.extract(url)
