"""Tests for AI anomaly detection."""
import pytest
from app.ai.anomaly import AnomalyDetector, BootFeatureVector, AnomalyResult


@pytest.fixture
def detector():
    return AnomalyDetector(threshold=0.3)


def make_normal_features(**overrides):
    defaults = dict(
        boot_duration_ms=150.0,
        stage_count=7,
        passed_stages=7,
        stage_durations=[20.0] * 7,
        sig_check_time_ms=50.0,
        puf_read_time_ms=20.0,
        error_count=0,
        error_codes=[],
        attack_type=None,
    )
    defaults.update(overrides)
    return BootFeatureVector(**defaults)


class TestAnomalyDetector:
    def test_normal_boot_not_anomalous(self, detector):
        features = make_normal_features()
        result = detector.analyze(features)
        assert not result.is_anomalous
        assert result.score < 0.5

    def test_zero_duration_anomalous(self, detector):
        features = make_normal_features(boot_duration_ms=0.0)
        result = detector.analyze(features)
        assert result.is_anomalous or result.score > 0.3

    def test_stage_failure_anomalous(self, detector):
        features = make_normal_features(stage_count=7, passed_stages=2)
        result = detector.analyze(features)
        assert result.is_anomalous

    def test_error_count_increases_score(self, detector):
        clean = detector.analyze(make_normal_features(error_count=0))
        dirty = detector.analyze(make_normal_features(error_count=5))
        assert dirty.score >= clean.score

    def test_attack_type_flagged(self, detector):
        features = make_normal_features(attack_type="clone_device")
        result = detector.analyze(features)
        assert result.is_anomalous
        assert any("clone" in r.lower() for r in result.reasons)

    def test_excessive_duration(self, detector):
        features = make_normal_features(boot_duration_ms=2000.0)
        result = detector.analyze(features)
        assert result.is_anomalous

    def test_result_has_all_fields(self, detector):
        result = detector.analyze(make_normal_features())
        assert isinstance(result, AnomalyResult)
        assert 0 <= result.score <= 1
        assert isinstance(result.reasons, list)
        assert isinstance(result.feature_scores, dict)
        assert 0 <= result.confidence <= 1

    def test_trend_stable(self, detector):
        for _ in range(5):
            detector.analyze(make_normal_features())
        trend = detector.get_trend()
        assert trend["trend"] == "stable"
        assert trend["samples"] == 5

    def test_features_to_dict(self):
        f = make_normal_features()
        d = f.to_dict()
        assert "boot_duration_ms" in d
        assert "stage_count" in d

    def test_deterministic(self, detector):
        f = make_normal_features()
        r1 = detector.analyze(f)
        r2 = detector.analyze(f)
        assert r1.score == r2.score
