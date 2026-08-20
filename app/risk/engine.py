"""Multi-layer risk correlation engine.

Aggregates signals from multiple security subsystems into a unified
risk assessment.  Combines:
- Boot verification results (signature, chain, firmware integrity)
- PUF matching confidence
- Anomaly detection scores
- Environmental conditions
- Attack detection signals
- Transparency log status
- PQC signature status

Produces a composite RiskScore with per-layer breakdown and
recommended action (ALLOW / WARN / DENY).
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum


class RiskLevel(Enum):
    """Risk classification levels."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class RiskAction(Enum):
    """Recommended action based on risk assessment."""
    ALLOW = "ALLOW"
    WARN = "WARN"
    DENY = "DENY"


@dataclass
class RiskLayer:
    """A single risk layer input."""
    name: str
    score: float        # 0.0 (safe) to 1.0 (critical)
    weight: float       # relative importance (0-1)
    details: dict = field(default_factory=dict)

    @property
    def weighted_score(self) -> float:
        return self.score * self.weight


@dataclass
class RiskScore:
    """Composite risk assessment result."""
    overall_score: float          # 0.0 (safe) to 1.0 (critical)
    level: RiskLevel
    action: RiskAction
    layers: list[RiskLayer]
    recommendations: list[str]
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict:
        return {
            "overall_score": round(self.overall_score, 4),
            "level": self.level.value,
            "action": self.action.value,
            "layers": [
                {
                    "name": l.name,
                    "score": round(l.score, 4),
                    "weight": round(l.weight, 4),
                    "weighted_score": round(l.weighted_score, 4),
                    "details": l.details,
                }
                for l in self.layers
            ],
            "recommendations": self.recommendations,
            "timestamp": self.timestamp,
        }


class RiskEngine:
    """Multi-layer risk correlation engine.

    Architecture:
        1. Collect risk layers from all subsystems
        2. Compute weighted composite score
        3. Apply decision logic with hysteresis
        4. Generate recommendations

    Decision thresholds:
        score < 0.3 → ALLOW
        0.3 ≤ score < 0.6 → WARN (log, may allow with extra checks)
        score ≥ 0.6 → DENY
    """

    THRESHOLD_WARN = 0.3
    THRESHOLD_DENY = 0.6

    # Layer weights (must sum to 1.0)
    DEFAULT_WEIGHTS = {
        "signature": 0.25,
        "chain_of_trust": 0.20,
        "puf_match": 0.15,
        "anomaly": 0.15,
        "environmental": 0.05,
        "transparency": 0.10,
        "pqc": 0.10,
    }

    def __init__(self, weights: dict[str, float] | None = None) -> None:
        self.weights = weights or dict(self.DEFAULT_WEIGHTS)
        self._history: list[RiskScore] = []

    def assess(
        self,
        signature_valid: bool = True,
        chain_valid: bool = True,
        puf_match_score: float = 1.0,
        anomaly_score: float = 0.0,
        anomaly_is_anomalous: bool = False,
        environmental_stability: float = 1.0,
        transparency_log_valid: bool = True,
        pqc_valid: bool = True,
        firmware_integrity: bool = True,
        known_attack: str | None = None,
        previous_score: float | None = None,
    ) -> RiskScore:
        """Compute a composite risk score from all subsystem signals.

        Args:
            signature_valid: Is the firmware signature valid?
            chain_valid: Is the chain of trust intact?
            puf_match_score: PUF matching confidence (0-1, 1 = perfect match)
            anomaly_score: AI anomaly detection score (0-1, 1 = very anomalous)
            anomaly_is_anomalous: Did the anomaly detector flag this?
            environmental_stability: PUF stability under current conditions (0-1)
            transparency_log_valid: Is the firmware in the transparency log?
            pqc_valid: Is the post-quantum signature valid?
            firmware_integrity: Does firmware hash match expected?
            known_attack: Type of known attack if any
            previous_score: Previous risk score for hysteresis
        """
        layers: list[RiskLayer] = []

        # 1. Signature verification
        sig_score = 0.0 if signature_valid else 0.9
        layers.append(RiskLayer(
            name="signature",
            score=sig_score,
            weight=self.weights.get("signature", 0.25),
            details={"valid": signature_valid},
        ))

        # 2. Chain of trust
        chain_score = 0.0 if chain_valid else 0.85
        layers.append(RiskLayer(
            name="chain_of_trust",
            score=chain_score,
            weight=self.weights.get("chain_of_trust", 0.20),
            details={"valid": chain_valid},
        ))

        # 3. PUF match
        puf_score = 1.0 - puf_match_score  # invert: high match → low risk
        layers.append(RiskLayer(
            name="puf_match",
            score=puf_score,
            weight=self.weights.get("puf_match", 0.15),
            details={"match_score": puf_match_score, "stability": environmental_stability},
        ))

        # 4. Anomaly detection
        anomaly_risk = anomaly_score
        layers.append(RiskLayer(
            name="anomaly",
            score=anomaly_risk,
            weight=self.weights.get("anomaly", 0.15),
            details={"score": anomaly_score, "flagged": anomaly_is_anomalous},
        ))

        # 5. Environmental conditions
        env_score = 1.0 - environmental_stability
        layers.append(RiskLayer(
            name="environmental",
            score=env_score,
            weight=self.weights.get("environmental", 0.05),
            details={"stability": environmental_stability},
        ))

        # 6. Transparency log
        tl_score = 0.0 if transparency_log_valid else 0.7
        layers.append(RiskLayer(
            name="transparency",
            score=tl_score,
            weight=self.weights.get("transparency", 0.10),
            details={"valid": transparency_log_valid},
        ))

        # 7. PQC verification
        pqc_score = 0.0 if pqc_valid else 0.8
        layers.append(RiskLayer(
            name="pqc",
            score=pqc_score,
            weight=self.weights.get("pqc", 0.10),
            details={"valid": pqc_valid},
        ))

        # Composite score
        total_weight = sum(l.weight for l in layers)
        if total_weight > 0:
            composite = sum(l.weighted_score for l in layers) / total_weight
        else:
            composite = 0.0

        # Amplify if known attack
        if known_attack:
            composite = min(composite + 0.3, 1.0)

        # Hysteresis: if previous score was high, make it harder to drop
        if previous_score is not None and previous_score > 0.5:
            composite = max(composite, previous_score * 0.8)

        # Classify
        if composite < self.THRESHOLD_WARN:
            level = RiskLevel.LOW
            action = RiskAction.ALLOW
        elif composite < self.THRESHOLD_DENY:
            level = RiskLevel.MEDIUM
            action = RiskAction.WARN
        else:
            level = RiskLevel.HIGH if composite < 0.85 else RiskLevel.CRITICAL
            action = RiskAction.DENY

        # Generate recommendations
        recommendations = self._generate_recommendations(layers, level, known_attack)

        result = RiskScore(
            overall_score=composite,
            level=level,
            action=action,
            layers=layers,
            recommendations=recommendations,
        )

        self._history.append(result)
        return result

    def _generate_recommendations(
        self, layers: list[RiskLayer], level: RiskLevel, known_attack: str | None
    ) -> list[str]:
        """Generate actionable recommendations based on risk assessment."""
        recs = []

        for layer in layers:
            if layer.score > 0.5:
                if layer.name == "signature":
                    recs.append("FIRMWARE REJECTED: Invalid signature. Reflash from trusted source.")
                elif layer.name == "chain_of_trust":
                    recs.append("CHAIN BROKEN: Chain of trust compromised. Check root certificate and key rotation.")
                elif layer.name == "puf_match":
                    recs.append("PUF MISMATCH: Device identity cannot be verified. Possible device spoofing.")
                elif layer.name == "anomaly":
                    recs.append("ANOMALY DETECTED: Unusual boot pattern. Investigate potential tampering.")
                elif layer.name == "transparency":
                    recs.append("TRANSPARENCY LOG: Firmware not in transparency log. Possible unauthorized firmware.")
                elif layer.name == "pqc":
                    recs.append("PQC FAILURE: Post-quantum signature invalid. Check for quantum-resistant key compromise.")
                elif layer.name == "environmental":
                    recs.append("ENVIRONMENTAL: Abnormal operating conditions affecting PUF reliability.")

        if known_attack:
            recs.append(f"ATTACK DETECTED: {known_attack}. Immediate isolation recommended.")

        if level == RiskLevel.CRITICAL:
            recs.append("CRITICAL: Device should be immediately quarantined and investigated.")
        elif level == RiskLevel.HIGH:
            recs.append("HIGH RISK: Boot should be halted pending manual review.")
        elif level == RiskLevel.MEDIUM:
            recs.append("MEDIUM RISK: Continue boot with enhanced monitoring.")
        else:
            recs.append("LOW RISK: Normal boot proceeding.")

        return recs

    def get_history(self, limit: int = 20) -> list[dict]:
        """Get recent risk assessment history."""
        return [r.to_dict() for r in self._history[-limit:]]
