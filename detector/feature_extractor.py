import re
from urllib.parse import urlparse

import pandas as pd


class URLFeatureExtractor:

    SHORTENING_SERVICES = [
        "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly",
        "is.gd", "buff.ly", "adf.ly", "bit.do", "cutt.ly",
        "rb.gy", "short.io", "tiny.cc", "lnkd.in", "soo.gd",
    ]

    SUSPICIOUS_WORDS = [
        "login", "secure", "account", "verify", "update",
        "confirm", "banking",
    ]

    def extract(self, url: str) -> dict:
        try:
            parsed = urlparse(url)
            features = {
                "url_length":             self._get_url_length(url),
                "domain_length":          self._get_domain_length(parsed),
                "path_length":            self._get_path_length(parsed),
                "has_ip_address":         self._get_has_ip_address(parsed),
                "has_at_symbol":          self._get_has_at_symbol(url),
                "has_double_slash":       self._get_has_double_slash(parsed),
                "has_hyphen_domain":      self._get_has_hyphen_domain(parsed),
                "count_dots":             self._get_count_dots(url),
                "count_hyphens":          self._get_count_hyphens(url),
                "count_slash":            self._get_count_slash(url),
                "count_digits":           self._get_count_digits(url),
                "count_special_chars":    self._get_count_special_chars(url),
                "has_https":              self._get_has_https(parsed),
                "has_shortening_service": self._get_has_shortening_service(parsed),
                "url_depth":              self._get_url_depth(parsed),
                "digit_ratio":            self._get_digit_ratio(url),
                "has_suspicious_words":   self._get_has_suspicious_words(url),
            }
            return features
        except Exception:
            return self._get_empty_features()

    def extract_batch(self, urls: list) -> pd.DataFrame:
        rows = [self.extract(url) for url in urls]
        return pd.DataFrame(rows)

    def _get_url_length(self, url: str) -> int:
        return len(url)

    def _get_domain_length(self, parsed) -> int:
        return len(parsed.netloc)

    def _get_path_length(self, parsed) -> int:
        return len(parsed.path)

    def _get_has_ip_address(self, parsed) -> int:
        hostname = parsed.hostname or ""
        ipv4_pattern = r"^(\d{1,3}\.){3}\d{1,3}$"
        if re.match(ipv4_pattern, hostname):
            return 1
        if hostname.startswith("[") or ":" in hostname:
            return 1
        return 0

    def _get_has_at_symbol(self, url: str) -> int:
        return 1 if "@" in url else 0

    def _get_has_double_slash(self, parsed) -> int:
        return 1 if "//" in parsed.path else 0

    def _get_has_hyphen_domain(self, parsed) -> int:
        return 1 if "-" in parsed.netloc else 0

    def _get_count_dots(self, url: str) -> int:
        return url.count(".")

    def _get_count_hyphens(self, url: str) -> int:
        return url.count("-")

    def _get_count_slash(self, url: str) -> int:
        return url.count("/")

    def _get_count_digits(self, url: str) -> int:
        return sum(c.isdigit() for c in url)

    def _get_count_special_chars(self, url: str) -> int:
        special = {"@", "?", "=", "&", "%"}
        return sum(c in special for c in url)

    def _get_has_https(self, parsed) -> int:
        return 1 if parsed.scheme.lower() == "https" else 0

    def _get_has_shortening_service(self, parsed) -> int:
        domain = parsed.netloc.lower()
        for service in self.SHORTENING_SERVICES:
            if service in domain:
                return 1
        return 0

    def _get_url_depth(self, parsed) -> int:
        path = parsed.path.strip("/")
        if not path:
            return 0
        return len(path.split("/"))

    def _get_digit_ratio(self, url: str) -> float:
        length = len(url)
        if length == 0:
            return 0.0
        return sum(c.isdigit() for c in url) / length

    def _get_has_suspicious_words(self, url: str) -> int:
        url_lower = url.lower()
        for word in self.SUSPICIOUS_WORDS:
            if word in url_lower:
                return 1
        return 0

    def _get_empty_features(self) -> dict:
        return {
            "url_length": 0,
            "domain_length": 0,
            "path_length": 0,
            "has_ip_address": 0,
            "has_at_symbol": 0,
            "has_double_slash": 0,
            "has_hyphen_domain": 0,
            "count_dots": 0,
            "count_hyphens": 0,
            "count_slash": 0,
            "count_digits": 0,
            "count_special_chars": 0,
            "has_https": 0,
            "has_shortening_service": 0,
            "url_depth": 0,
            "digit_ratio": 0.0,
            "has_suspicious_words": 0,
        }
