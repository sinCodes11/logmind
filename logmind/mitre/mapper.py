"""MITRE ATT&CK technique mapper."""

from dataclasses import dataclass, field

from logmind.detection.detector import DetectionResult
from logmind.mitre.attack_data import ATTACKData


@dataclass
class TechniqueInfo:
    """Mapped technique information."""

    technique_id: str
    technique_name: str
    tactics: list[str]
    description: str
    url: str
    confidence: float = 1.0
    source: str = "detection"


class ATTACKMapper:
    """
    Maps detection results to MITRE ATT&CK techniques.

    Enriches detections with full technique information.
    """

    def __init__(self, data_path: str | None = None) -> None:
        """
        Initialize the mapper.

        Args:
            data_path: Optional path to STIX JSON file
        """
        self._attack_data = ATTACKData(data_path)

    def map_detection(self, detection: DetectionResult) -> list[TechniqueInfo]:
        """
        Map a detection result to ATT&CK techniques.

        Args:
            detection: DetectionResult to map

        Returns:
            List of TechniqueInfo with full technique details
        """
        techniques = []
        seen = set()

        for tech_id in detection.mitre_techniques:
            if tech_id in seen:
                continue
            seen.add(tech_id)

            tech = self._attack_data.get_technique(tech_id)
            if tech:
                techniques.append(TechniqueInfo(
                    technique_id=tech.id,
                    technique_name=tech.name,
                    tactics=tech.tactics,
                    description=tech.description,
                    url=tech.url,
                    source="sigma" if detection.sigma_matches else "anomaly",
                ))

        return techniques

    def map_detections(
        self, detections: list[DetectionResult]
    ) -> dict[str, list[TechniqueInfo]]:
        """
        Map multiple detections to ATT&CK techniques.

        Args:
            detections: List of DetectionResult objects

        Returns:
            Dictionary mapping detection log_id to techniques
        """
        results = {}
        for detection in detections:
            techniques = self.map_detection(detection)
            if techniques:
                results[detection.log_id] = techniques
        return results

    def get_technique_details(self, technique_id: str) -> TechniqueInfo | None:
        """
        Get full details for a technique ID.

        Args:
            technique_id: MITRE technique ID (e.g., T1110)

        Returns:
            TechniqueInfo or None if not found
        """
        tech = self._attack_data.get_technique(technique_id)
        if not tech:
            return None

        return TechniqueInfo(
            technique_id=tech.id,
            technique_name=tech.name,
            tactics=tech.tactics,
            description=tech.description,
            url=tech.url,
        )

    def get_tactics_for_techniques(
        self, technique_ids: list[str]
    ) -> dict[str, list[str]]:
        """
        Get tactics associated with techniques.

        Args:
            technique_ids: List of technique IDs

        Returns:
            Dictionary mapping technique ID to tactics
        """
        results = {}
        for tech_id in technique_ids:
            tech = self._attack_data.get_technique(tech_id)
            if tech:
                results[tech_id] = tech.tactics
        return results

    def suggest_techniques(
        self, detection: DetectionResult
    ) -> list[TechniqueInfo]:
        """
        Suggest additional techniques based on detection context.

        Uses keywords and patterns to suggest possibly related techniques.

        Args:
            detection: DetectionResult to analyze

        Returns:
            List of suggested TechniqueInfo
        """
        suggestions = []
        keywords = []

        for match in detection.sigma_matches:
            keywords.extend(match.rule_name.lower().split())
            keywords.extend(match.description.lower().split())

        for anomaly in detection.anomalies:
            keywords.append(anomaly.anomaly_type.lower())
            keywords.extend(anomaly.description.lower().split())

        keyword_mapping = {
            "brute": ["T1110", "T1110.001"],
            "password": ["T1110", "T1552"],
            "sudo": ["T1548.003"],
            "privilege": ["T1548", "T1068"],
            "injection": ["T1190", "T1059"],
            "sql": ["T1190"],
            "traversal": ["T1083"],
            "shell": ["T1505.003", "T1059"],
            "scan": ["T1046", "T1595"],
            "exfiltration": ["T1041", "T1048"],
            "lateral": ["T1021", "T1570"],
        }

        already_mapped = set(detection.mitre_techniques)
        suggested_ids = set()

        for keyword in keywords:
            for pattern, tech_ids in keyword_mapping.items():
                if pattern in keyword:
                    for tech_id in tech_ids:
                        if tech_id not in already_mapped:
                            suggested_ids.add(tech_id)

        for tech_id in suggested_ids:
            info = self.get_technique_details(tech_id)
            if info:
                info.confidence = 0.6
                info.source = "suggestion"
                suggestions.append(info)

        return suggestions

    def generate_attack_narrative(
        self, techniques: list[TechniqueInfo]
    ) -> str:
        """
        Generate a narrative description of the attack.

        Args:
            techniques: List of techniques involved

        Returns:
            Human-readable attack narrative
        """
        if not techniques:
            return "No MITRE ATT&CK techniques identified."

        tactics_seen = set()
        for tech in techniques:
            tactics_seen.update(tech.tactics)

        tactic_order = [
            "Reconnaissance",
            "Resource Development",
            "Initial Access",
            "Execution",
            "Persistence",
            "Privilege Escalation",
            "Defense Evasion",
            "Credential Access",
            "Discovery",
            "Lateral Movement",
            "Collection",
            "Command and Control",
            "Exfiltration",
            "Impact",
        ]

        ordered_tactics = [t for t in tactic_order if t in tactics_seen]

        lines = ["## Attack Progression", ""]

        for tactic in ordered_tactics:
            lines.append(f"### {tactic}")
            for tech in techniques:
                if tactic in tech.tactics:
                    lines.append(f"- **{tech.technique_id}**: {tech.technique_name}")
            lines.append("")

        return "\n".join(lines)
