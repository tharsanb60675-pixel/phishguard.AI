"""
Zero-Day Behavioral Anomaly Detector.
Employs an Isolation Forest model to flag statistical outliers and anomalous structural profiles
that have no known signature or previous blacklist entry.
"""

import numpy as np
from typing import Dict, Any, Tuple
from sklearn.ensemble import IsolationForest
from app.ml.feature_extraction import FEATURE_NAMES, feature_dict_to_vector


class ZeroDayAnomalyDetector:
    def __init__(self):
        self.model = IsolationForest(
            n_estimators=120,
            contamination=0.08,
            random_state=42
        )
        self.is_trained = False
        self._initialize_baseline_model()

    def _initialize_baseline_model(self):
        """
        Train Isolation Forest on baseline legitimate Web traffic feature vectors.
        Outliers with high anomaly score represent novel, unclassified threats.
        """
        np.random.seed(42)
        n_samples = 400

        # Normal standard internet web traffic feature distribution
        baseline_data = np.zeros((n_samples, len(FEATURE_NAMES)))
        baseline_data[:, 0] = np.random.normal(25, 7, n_samples)     # url_len
        baseline_data[:, 1] = np.random.normal(12, 3, n_samples)     # host_len
        baseline_data[:, 2] = np.random.normal(8, 4, n_samples)      # path_len
        baseline_data[:, 3] = np.random.choice([0, 1], n_samples, p=[0.85, 0.15]) # subdomains
        baseline_data[:, 4] = np.random.normal(3.0, 0.25, n_samples) # entropy
        baseline_data[:, 5] = 0 # kw_cnt
        baseline_data[:, 6] = np.random.choice([0, 1], n_samples, p=[0.9, 0.1]) # hyphens
        baseline_data[:, 7] = 0 # at_cnt
        baseline_data[:, 8] = 0 # double_slash
        baseline_data[:, 9] = np.random.uniform(0.0, 0.04, n_samples) # digit_ratio
        baseline_data[:, 10] = 0 # is_ip
        baseline_data[:, 11] = 0 # punycode
        baseline_data[:, 12] = 1 # https
        baseline_data[:, 13] = np.random.uniform(0.05, 0.15, n_samples) # tld_wt
        baseline_data[:, 14] = np.random.uniform(600, 5000, n_samples)  # age_days
        baseline_data[:, 15] = np.random.uniform(120, 365, n_samples)   # ssl_days

        self.model.fit(baseline_data)
        self.is_trained = True

    def calculate_anomaly_score(self, feature_dict: Dict[str, Any]) -> Tuple[float, bool]:
        """
        Compute continuous zero-day anomaly score between 0.0 (Normal) and 1.0 (Extreme Anomaly).
        Returns (anomaly_score, is_zero_day_flag).
        """
        if feature_dict.get("is_trusted_brand") and feature_dict.get("subdomain_count", 0) <= 1:
            return 0.04, False

        vector = np.array([feature_dict_to_vector(feature_dict)])
        
        # Decision function: lower values mean more anomalous.
        raw_score = self.model.decision_function(vector)[0]
        # Invert and normalize to [0, 1] range:
        # Typical raw_score is in range [-0.5, +0.2]
        normalized_anomaly = float(np.clip(1.0 - (raw_score + 0.3) / 0.5, 0.0, 1.0))
        
        # High entropy + young domain + multiple subdomains strongly indicates novel zero-day attack
        if feature_dict.get("hostname_entropy", 0) > 3.9 and feature_dict.get("domain_age_days", 500) < 15:
            normalized_anomaly = max(normalized_anomaly, 0.85)

        is_zero_day = normalized_anomaly > 0.65
        return round(normalized_anomaly, 4), is_zero_day


zero_day_detector = ZeroDayAnomalyDetector()
