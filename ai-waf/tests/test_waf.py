"""
test_waf.py
-----------
Unit tests for the AI-WAF pipeline.

Run with:
    cd ai-waf/
    venv/Scripts/activate
    pytest tests/test_waf.py -v
"""

import sys, os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import pytest
import pandas as pd
import numpy as np
import joblib

# ── fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture(scope="module")
def model():
    return joblib.load("models/model_final.pkl")

@pytest.fixture(scope="module")
def scaler():
    return joblib.load("models/scaler.pkl")

@pytest.fixture(scope="module")
def processed_df():
    return pd.read_csv("data/processed.csv")

@pytest.fixture(scope="module")
def feature_cols(processed_df):
    return list(processed_df.drop(columns=["label"]).columns)


# ── 1. data_parser ────────────────────────────────────────────────────────────

class TestDataParser:

    def test_parser_returns_dataframe(self):
        from src.data_parser import load_dataset
        df = load_dataset()
        assert isinstance(df, pd.DataFrame)

    def test_parser_has_required_columns(self):
        from src.data_parser import load_dataset
        df = load_dataset()
        for col in ["method", "path", "query_string", "body", "label", "has_cookie"]:
            assert col in df.columns, f"Missing column: {col}"

    def test_parser_label_is_binary(self):
        from src.data_parser import load_dataset
        df = load_dataset()
        assert set(df["label"].unique()).issubset({0, 1})

    def test_parser_record_counts(self):
        from src.data_parser import load_dataset
        df = load_dataset()
        assert len(df) > 50_000, "Expected 60K+ records"
        assert (df["label"] == 0).sum() > 30_000
        assert (df["label"] == 1).sum() > 20_000

    def test_parser_no_null_labels(self):
        from src.data_parser import load_dataset
        df = load_dataset()
        assert df["label"].isnull().sum() == 0


# ── 2. feature_extractor ──────────────────────────────────────────────────────

class TestFeatureExtractor:

    def test_feature_count(self, processed_df):
        # 15 features + 1 label = 16 columns
        assert processed_df.shape[1] == 16

    def test_features_are_numeric(self, processed_df):
        X = processed_df.drop(columns=["label"])
        assert (X.dtypes == int).all() or (X.dtypes == float).all() or \
               all(d in [np.dtype("int64"), np.dtype("float64"), np.dtype("int32"), np.dtype("float32")]
                   for d in X.dtypes)

    def test_binary_flags_are_0_or_1(self, processed_df):
        flag_cols = ["method_is_post", "has_cookie", "has_sql", "has_xss",
                     "has_path_traversal", "has_cmd_injection", "has_null_byte"]
        for col in flag_cols:
            assert set(processed_df[col].unique()).issubset({0, 1}), \
                f"{col} has non-binary values"

    def test_no_negative_values(self, processed_df):
        X = processed_df.drop(columns=["label"])
        assert (X >= 0).all().all(), "Features should be non-negative"

    def test_normal_url_length_reasonable(self, processed_df):
        normal = processed_df[processed_df["label"] == 0]
        mean_len = normal["url_length"].mean()
        assert 50 < mean_len < 150, f"Expected url_length mean 50-150, got {mean_len:.1f}"

    def test_attack_higher_special_chars(self, processed_df):
        normal  = processed_df[processed_df["label"] == 0]["special_char_count"].mean()
        attacks = processed_df[processed_df["label"] == 1]["special_char_count"].mean()
        assert attacks > normal, "Attack requests should have more special chars on average"


# ── 3. logger ─────────────────────────────────────────────────────────────────

class TestLogger:

    def setup_method(self):
        """Wipe the DB before each test."""
        from src.logger import clear_all
        clear_all()

    def test_log_and_retrieve(self):
        from src.logger import log_event, get_recent
        log_event("GET", "http://localhost/test", "/test", 0.1, 0, "ALLOW", "127.0.0.1")
        events = get_recent(10)
        assert len(events) == 1
        assert events[0]["action"] == "ALLOW"
        assert events[0]["method"] == "GET"

    def test_stats_empty(self):
        from src.logger import get_stats
        stats = get_stats()
        assert stats["total"] == 0
        assert stats["blocked"] == 0

    def test_stats_with_events(self):
        from src.logger import log_event, get_stats
        log_event("GET",  "http://a.com/", "/", 0.1, 0, "ALLOW")
        log_event("POST", "http://a.com/", "/", 0.9, 1, "BLOCK")
        log_event("GET",  "http://a.com/", "/", 0.8, 1, "BLOCK")
        stats = get_stats()
        assert stats["total"] == 3
        assert stats["blocked"] == 2
        assert stats["allowed"] == 1
        assert stats["block_rate_pct"] == pytest.approx(66.67, abs=0.1)

    def test_log_stores_score(self):
        from src.logger import log_event, get_recent
        log_event("GET", "http://x.com/", "/", 0.7654, 1, "BLOCK")
        events = get_recent(1)
        assert events[0]["score"] == pytest.approx(0.7654, abs=0.001)

    def test_recent_limit(self):
        from src.logger import log_event, get_recent
        for i in range(20):
            log_event("GET", f"http://x.com/{i}", f"/{i}", 0.1, 0, "ALLOW")
        events = get_recent(5)
        assert len(events) == 5


# ── 4. proxy_interceptor ──────────────────────────────────────────────────────

class TestProxyInterceptor:

    @pytest.fixture(autouse=True)
    def load_interceptor(self):
        from src.proxy_interceptor import extract_features_from_request, WafAddon
        self.extract = extract_features_from_request
        self.addon   = WafAddon()

    def test_feature_vector_length(self, feature_cols):
        feats = self.extract("GET", "http://localhost:8080/tienda1/x.jsp", "/tienda1/x.jsp", "", "", {})
        assert len(feats) == len(feature_cols), \
            f"Expected {len(feature_cols)} features, got {len(feats)}"

    def test_post_flag(self):
        feats_get  = self.extract("GET",  "http://a.com/", "/", "", "", {})
        feats_post = self.extract("POST", "http://a.com/", "/", "", "", {})
        assert feats_get[0]  == 0.0
        assert feats_post[0] == 1.0

    def test_sql_flag_detected(self):
        feats = self.extract("GET", "http://a.com/?id=1 UNION SELECT * FROM users", "/",
                             "id=1 UNION SELECT * FROM users", "", {})
        assert feats[9] == 1.0, "has_sql should be 1"

    def test_xss_flag_detected(self):
        feats = self.extract("POST", "http://a.com/", "/", "", "<script>alert(1)</script>", {})
        assert feats[10] == 1.0, "has_xss should be 1"

    def test_path_traversal_detected(self):
        feats = self.extract("GET", "http://a.com/../../etc/passwd", "/../../etc/passwd", "", "", {})
        assert feats[11] == 1.0, "has_path_traversal should be 1"

    def test_normal_request_allowed(self, model, scaler, feature_cols):
        """Known-normal CSIC URL should score < 0.5."""
        feats = self.extract(
            "GET",
            "http://localhost:8080/tienda1/publico/vaciar.jsp?B2=Vaciar+carrito",
            "/tienda1/publico/vaciar.jsp",
            "B2=Vaciar+carrito", "",
            {"cookie": "JSESSIONID=ABC"},
        )
        df = pd.DataFrame([feats], columns=feature_cols)
        score = model.predict_proba(scaler.transform(df))[0][1]
        assert score < 0.5, f"Normal request should score < 0.5, got {score:.3f}"

    def test_sql_injection_blocked(self, model, scaler, feature_cols):
        """SQL injection request should score >= 0.5."""
        feats = self.extract(
            "GET",
            "http://localhost:8080/tienda1/publico/anadir.jsp?id=2' UNION SELECT * FROM users--",
            "/tienda1/publico/anadir.jsp",
            "id=2' UNION SELECT * FROM users--", "", {},
        )
        df = pd.DataFrame([feats], columns=feature_cols)
        score = model.predict_proba(scaler.transform(df))[0][1]
        assert score >= 0.5, f"SQLi should score >= 0.5, got {score:.3f}"

    def test_xss_blocked(self, model, scaler, feature_cols):
        """XSS request should score >= 0.5."""
        feats = self.extract(
            "POST",
            "http://localhost:8080/tienda1/publico/autenticar.jsp",
            "/tienda1/publico/autenticar.jsp",
            "", "login=admin&pwd=<script>alert(1)</script>",
            {"content-length": "50"},
        )
        df = pd.DataFrame([feats], columns=feature_cols)
        score = model.predict_proba(scaler.transform(df))[0][1]
        assert score >= 0.5, f"XSS should score >= 0.5, got {score:.3f}"

    def test_path_traversal_blocked(self, model, scaler, feature_cols):
        """Path traversal should score >= 0.5."""
        feats = self.extract(
            "GET",
            "http://localhost:8080/tienda1/publico/../../etc/passwd",
            "/tienda1/publico/../../etc/passwd",
            "", "", {},
        )
        df = pd.DataFrame([feats], columns=feature_cols)
        score = model.predict_proba(scaler.transform(df))[0][1]
        assert score >= 0.5, f"Path traversal should score >= 0.5, got {score:.3f}"


# ── 5. model artefacts ────────────────────────────────────────────────────────

class TestModelArtefacts:

    def test_model_file_exists(self):
        assert os.path.exists("models/model_final.pkl")

    def test_scaler_file_exists(self):
        assert os.path.exists("models/scaler.pkl")

    def test_model_has_predict_proba(self, model):
        assert hasattr(model, "predict_proba")

    def test_model_n_estimators(self, model):
        assert model.n_estimators == 200

    def test_eval_metrics_exist(self):
        metrics = pd.read_csv("models/eval_results.csv")
        for col in ["Accuracy", "Precision", "Recall", "F1", "ROC-AUC"]:
            assert col in metrics.columns

    def test_roc_auc_above_threshold(self):
        metrics = pd.read_csv("models/eval_results.csv")
        assert metrics["ROC-AUC"].iloc[0] > 0.90, "ROC-AUC should be > 0.90"

    def test_recall_above_threshold(self):
        metrics = pd.read_csv("models/eval_results.csv")
        assert metrics["Recall"].iloc[0] > 0.85, "Recall should be > 0.85 for a WAF"
