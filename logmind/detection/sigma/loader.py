"""Sigma rule loader and management."""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml


@dataclass
class SigmaRule:
    """Parsed Sigma rule representation."""

    id: str
    title: str
    status: str
    level: str
    description: str
    author: str | None = None
    date: str | None = None
    modified: str | None = None
    references: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    logsource: dict[str, str] = field(default_factory=dict)
    detection: dict[str, Any] = field(default_factory=dict)
    falsepositives: list[str] = field(default_factory=list)
    file_path: Path | None = None

    @property
    def mitre_tactics(self) -> list[str]:
        """Extract MITRE ATT&CK tactics from tags."""
        tactics = []
        for tag in self.tags:
            if tag.startswith("attack."):
                part = tag.split(".")[1]
                if not part.startswith("t") and not part[0].isdigit():
                    tactics.append(part.replace("_", " ").title())
        return tactics

    @property
    def mitre_techniques(self) -> list[str]:
        """Extract MITRE ATT&CK technique IDs from tags."""
        techniques = []
        for tag in self.tags:
            if tag.startswith("attack.t"):
                tech_id = tag.split(".")[1].upper()
                techniques.append(tech_id)
        return techniques


class RuleLoader:
    """
    Load and manage Sigma rules from filesystem.

    Supports recursive directory scanning and rule validation.
    """

    def __init__(self, rules_path: str | Path) -> None:
        """
        Initialize rule loader.

        Args:
            rules_path: Base path for Sigma rules
        """
        self.rules_path = Path(rules_path)
        self._rules: dict[str, SigmaRule] = {}

    def load_rules(self) -> dict[str, SigmaRule]:
        """
        Load all Sigma rules from the rules directory.

        Returns:
            Dictionary mapping rule ID to SigmaRule
        """
        self._rules.clear()

        if not self.rules_path.exists():
            return self._rules

        for yaml_file in self.rules_path.rglob("*.yml"):
            try:
                rule = self._load_rule_file(yaml_file)
                if rule:
                    self._rules[rule.id] = rule
            except Exception:
                continue

        for yaml_file in self.rules_path.rglob("*.yaml"):
            try:
                rule = self._load_rule_file(yaml_file)
                if rule:
                    self._rules[rule.id] = rule
            except Exception:
                continue

        return self._rules

    def _load_rule_file(self, file_path: Path) -> SigmaRule | None:
        """Load a single Sigma rule from a YAML file."""
        with open(file_path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)

        if not data or not isinstance(data, dict):
            return None

        if "detection" not in data:
            return None

        rule_id = data.get("id", str(file_path.stem))

        return SigmaRule(
            id=rule_id,
            title=data.get("title", "Unknown Rule"),
            status=data.get("status", "experimental"),
            level=data.get("level", "medium"),
            description=data.get("description", ""),
            author=data.get("author"),
            date=data.get("date"),
            modified=data.get("modified"),
            references=data.get("references", []),
            tags=data.get("tags", []),
            logsource=data.get("logsource", {}),
            detection=data.get("detection", {}),
            falsepositives=data.get("falsepositives", []),
            file_path=file_path,
        )

    def get_rule(self, rule_id: str) -> SigmaRule | None:
        """Get a specific rule by ID."""
        return self._rules.get(rule_id)

    def get_rules_by_level(self, level: str) -> list[SigmaRule]:
        """Get rules filtered by severity level."""
        return [r for r in self._rules.values() if r.level == level]

    def get_rules_by_logsource(
        self,
        product: str | None = None,
        category: str | None = None,
        service: str | None = None,
    ) -> list[SigmaRule]:
        """Get rules matching a log source."""
        results = []
        for rule in self._rules.values():
            logsource = rule.logsource
            if product and logsource.get("product") != product:
                continue
            if category and logsource.get("category") != category:
                continue
            if service and logsource.get("service") != service:
                continue
            results.append(rule)
        return results

    @property
    def rule_count(self) -> int:
        """Get total number of loaded rules."""
        return len(self._rules)

    @property
    def rules(self) -> list[SigmaRule]:
        """Get all loaded rules."""
        return list(self._rules.values())
