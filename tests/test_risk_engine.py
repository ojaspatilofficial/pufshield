"""Tests for risk correlation engine."""
import pytest
from app.risk.engine import RiskEngine, RiskLevel, RiskAction


@pytest.fixture
def engine():
    return RiskEngine()


class TestRiskEngine:
    def test_all_valid_low_risk(self, engine):
        result = engine.assess(
            signature_valid=True,
            chain_valid=True,
            puf_match_score=1.0,
            anomaly_score=0.0,
            transparency_log_valid=True,
            pqc_valid=True,
        )
        assert result.level == RiskLevel.LOW
        assert result.action == RiskAction.ALLOW
        assert result.overall_score < 0.3

    def test_signature_invalid_high_risk(self, engine):
        result = engine.assess(
            signature_valid=False,
            chain_valid=False,
            puf_match_score=0.0,
            anomaly_score=0.9,
            transparency_log_valid=False,
            pqc_valid=False,
        )
        assert result.level in (RiskLevel.HIGH, RiskLevel.CRITICAL)
        assert result.action == RiskAction.DENY

    def test_puf_mismatch_risk(self, engine):
        result = engine.assess(puf_match_score=0.3)
        assert result.overall_score > 0.1

    def test_known_attack_amplifies(self, engine):
        normal = engine.assess()
        attacked = engine.assess(known_attack="clone_device")
        assert attacked.overall_score > normal.overall_score

    def test_recommendations_generated(self, engine):
        result = engine.assess(signature_valid=False)
        assert len(result.recommendations) > 0

    def test_result_to_dict(self, engine):
        result = engine.assess()
        d = result.to_dict()
        assert "overall_score" in d
        assert "level" in d
        assert "action" in d
        assert "layers" in d
        assert "recommendations" in d

    def test_history(self, engine):
        engine.assess()
        engine.assess(signature_valid=False)
        history = engine.get_history()
        assert len(history) == 2

    def test_hysteresis(self, engine):
        # First: high risk
        r1 = engine.assess(signature_valid=False, previous_score=0.8)
        # Then: better signals but previous was high
        r2 = engine.assess(signature_valid=True, previous_score=r1.overall_score)
        # Hysteresis should prevent instant drop
        assert r2.overall_score >= r1.overall_score * 0.5

    def test_layer_weights(self, engine):
        result = engine.assess()
        weights = [l.weight for l in result.layers]
        assert abs(sum(weights) - 1.0) < 0.01  # approximately sum to 1

    def test_all_layers_present(self, engine):
        result = engine.assess()
        layer_names = {l.name for l in result.layers}
        expected = {"signature", "chain_of_trust", "puf_match", "anomaly", "environmental", "transparency", "pqc"}
        assert expected == layer_names
