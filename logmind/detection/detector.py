"""Detection orchestrator combining Sigma rules and anomaly detection."""

from dataclasses import dataclass, field
from typing import Sequence

from logmind.detection.anomaly.detector import AnomalyDetector, AnomalyResult
from logmind.detection.sigma.engine import SigmaEngine, SigmaMatch
from logmind.ingestion.base import NormalizedLog


@dataclass
class DetectionResult:
    """Combined detection result from all engines."""

    log_id: str
    log_timestamp: str
    source: str
    sigma_matches: list[SigmaMatch] = field(default_factory=list)
    anomalies: list[AnomalyResult] = field(default_factory=list)

    @property
    def has_detections(self) -> bool:
        """Check if any detections were found."""
        return bool(self.sigma_matches or self.anomalies)

    @property
    def max_severity(self) -> str:
        """Get the highest severity across all detections."""
        severity_order = ["critical", "high", "medium", "low", "informational"]

        severities = []
        for match in self.sigma_matches:
            severities.append(match.level.lower())
        for anomaly in self.anomalies:
            severities.append(anomaly.severity.lower())

        if not severities:
            return "informational"

        for sev in severity_order:
            if sev in severities:
                return sev

        return "informational"

    @property
    def mitre_tactics(self) -> list[str]:
        """Get all unique MITRE tactics."""
        tactics = set()
        for match in self.sigma_matches:
            tactics.update(match.mitre_tactics)
        for anomaly in self.anomalies:
            if anomaly.mitre_tactic:
                tactics.add(anomaly.mitre_tactic)
        return list(tactics)

    @property
    def mitre_techniques(self) -> list[str]:
        """Get all unique MITRE techniques."""
        techniques = set()
        for match in self.sigma_matches:
            techniques.update(match.mitre_techniques)
        for anomaly in self.anomalies:
            if anomaly.mitre_technique:
                techniques.add(anomaly.mitre_technique)
        return list(techniques)


class DetectionOrchestrator:
    """
    Orchestrates multiple detection engines.

    Combines Sigma rule matching and statistical anomaly detection
    for comprehensive threat detection.
    """

    def __init__(
        self,
        sigma_rules_path: str = "rules",
        enable_sigma: bool = True,
        enable_anomaly: bool = True,
    ) -> None:
        """
        Initialize the detection orchestrator.

        Args:
            sigma_rules_path: Path to Sigma rules directory
            enable_sigma: Enable Sigma rule detection
            enable_anomaly: Enable anomaly detection
        """
        self.enable_sigma = enable_sigma
        self.enable_anomaly = enable_anomaly

        self._sigma_engine: SigmaEngine | None = None
        self._anomaly_detector: AnomalyDetector | None = None

        if enable_sigma:
            self._sigma_engine = SigmaEngine(sigma_rules_path)
            self._sigma_engine.load_rules()

        if enable_anomaly:
            self._anomaly_detector = AnomalyDetector()

    def detect(self, log: NormalizedLog) -> DetectionResult:
        """
        Run all detection engines on a single log.

        Args:
            log: NormalizedLog to analyze

        Returns:
            DetectionResult with all findings
        """
        result = DetectionResult(
            log_id=log.id,
            log_timestamp=log.timestamp.isoformat(),
            source=log.source,
        )

        if self._sigma_engine:
            result.sigma_matches = self._sigma_engine.evaluate(log)

        if self._anomaly_detector:
            result.anomalies = self._anomaly_detector.analyze(log)

        return result

    def detect_batch(
        self, logs: Sequence[NormalizedLog]
    ) -> list[DetectionResult]:
        """
        Run detection on multiple logs.

        Args:
            logs: Sequence of logs to analyze

        Returns:
            List of DetectionResult objects (only those with detections)
        """
        results = []
        for log in logs:
            result = self.detect(log)
            if result.has_detections:
                results.append(result)
        return results

    def reload_rules(self) -> int:
        """
        Reload Sigma rules from disk.

        Returns:
            Number of rules loaded
        """
        if self._sigma_engine:
            return self._sigma_engine.load_rules()
        return 0

    def get_stats(self) -> dict:
        """Get detection engine statistics."""
        stats = {
            "sigma_enabled": self.enable_sigma,
            "anomaly_enabled": self.enable_anomaly,
            "sigma_rules_loaded": 0,
            "sigma_rules_by_level": {},
        }

        if self._sigma_engine:
            stats["sigma_rules_loaded"] = self._sigma_engine.rule_count
            stats["sigma_rules_by_level"] = self._sigma_engine.get_rules_summary()

        return stats

    def reset_anomaly_state(self) -> None:
        """Reset anomaly detector state."""
        if self._anomaly_detector:
            self._anomaly_detector.reset_state()
