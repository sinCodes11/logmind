"""Sigma rules detection engine."""

import re
from dataclasses import dataclass, field
from typing import Any

from logmind.detection.sigma.loader import RuleLoader, SigmaRule
from logmind.ingestion.base import NormalizedLog


@dataclass
class SigmaMatch:
    """Result of a Sigma rule match."""

    rule_id: str
    rule_name: str
    level: str
    description: str
    matched_fields: dict[str, Any] = field(default_factory=dict)
    mitre_tactics: list[str] = field(default_factory=list)
    mitre_techniques: list[str] = field(default_factory=list)


class SigmaEngine:
    """
    Sigma rule matching engine.

    Evaluates normalized logs against loaded Sigma rules using
    pattern matching on log fields.
    """

    def __init__(self, rules_path: str = "rules") -> None:
        """
        Initialize the Sigma engine.

        Args:
            rules_path: Path to Sigma rules directory
        """
        self.loader = RuleLoader(rules_path)
        self._rules: dict[str, SigmaRule] = {}

    def load_rules(self) -> int:
        """
        Load all Sigma rules.

        Returns:
            Number of rules loaded
        """
        self._rules = self.loader.load_rules()
        return len(self._rules)

    def evaluate(self, log: NormalizedLog) -> list[SigmaMatch]:
        """
        Evaluate a log against all loaded rules.

        Args:
            log: NormalizedLog to evaluate

        Returns:
            List of matching SigmaMatch results
        """
        matches = []
        log_dict = self._log_to_dict(log)

        for rule in self._rules.values():
            match_result = self._evaluate_rule(rule, log_dict)
            if match_result:
                matches.append(match_result)

        return matches

    def evaluate_batch(
        self, logs: list[NormalizedLog]
    ) -> dict[str, list[SigmaMatch]]:
        """
        Evaluate multiple logs against all rules.

        Args:
            logs: List of NormalizedLog entries

        Returns:
            Dictionary mapping log ID to list of matches
        """
        results = {}
        for log in logs:
            matches = self.evaluate(log)
            if matches:
                results[log.id] = matches
        return results

    def _log_to_dict(self, log: NormalizedLog) -> dict[str, Any]:
        """Convert NormalizedLog to dictionary for matching."""
        data = {
            "timestamp": str(log.timestamp),
            "source": log.source,
            "source_type": log.source_type,
            "severity": log.severity.value,
            "facility": log.facility,
            "program": log.program,
            "pid": log.pid,
            "message": log.message,
            "raw": log.raw,
            "src_ip": log.src_ip,
            "src_port": log.src_port,
            "dst_ip": log.dst_ip,
            "dst_port": log.dst_port,
            "user": log.user,
        }
        data.update(log.extensions)
        return {k: v for k, v in data.items() if v is not None}

    def _evaluate_rule(
        self, rule: SigmaRule, log_dict: dict[str, Any]
    ) -> SigmaMatch | None:
        """Evaluate a single rule against a log."""
        detection = rule.detection
        if not detection:
            return None

        condition = detection.get("condition", "")
        if not condition:
            return None

        selection_results = {}
        for key, value in detection.items():
            if key == "condition":
                continue
            if isinstance(value, dict):
                selection_results[key] = self._match_selection(value, log_dict)
            elif isinstance(value, list):
                selection_results[key] = any(
                    self._match_selection(item, log_dict)
                    for item in value
                    if isinstance(item, dict)
                )

        if self._evaluate_condition(condition, selection_results):
            matched_fields = {
                k: log_dict.get(k)
                for k in log_dict
                if log_dict.get(k)
            }
            return SigmaMatch(
                rule_id=rule.id,
                rule_name=rule.title,
                level=rule.level,
                description=rule.description,
                matched_fields=matched_fields,
                mitre_tactics=rule.mitre_tactics,
                mitre_techniques=rule.mitre_techniques,
            )

        return None

    def _match_selection(
        self, selection: dict[str, Any], log_dict: dict[str, Any]
    ) -> bool:
        """Match a selection block against log fields."""
        for field_spec, patterns in selection.items():
            field_name = field_spec.split("|")[0]
            modifiers = field_spec.split("|")[1:] if "|" in field_spec else []

            log_value = log_dict.get(field_name)
            if log_value is None:
                if field_name == "message":
                    log_value = log_dict.get("raw", "")
                else:
                    return False

            log_value_str = str(log_value).lower()

            if not isinstance(patterns, list):
                patterns = [patterns]

            matched = False
            for pattern in patterns:
                if pattern is None:
                    continue
                pattern_str = str(pattern).lower()

                if "contains" in modifiers:
                    if pattern_str in log_value_str:
                        matched = True
                        break
                elif "startswith" in modifiers:
                    if log_value_str.startswith(pattern_str):
                        matched = True
                        break
                elif "endswith" in modifiers:
                    if log_value_str.endswith(pattern_str):
                        matched = True
                        break
                elif "re" in modifiers:
                    try:
                        if re.search(pattern_str, log_value_str):
                            matched = True
                            break
                    except re.error:
                        pass
                else:
                    if "*" in pattern_str:
                        regex = pattern_str.replace("*", ".*")
                        try:
                            if re.fullmatch(regex, log_value_str):
                                matched = True
                                break
                        except re.error:
                            pass
                    elif pattern_str == log_value_str:
                        matched = True
                        break

            if not matched:
                return False

        return True

    def _evaluate_condition(
        self, condition: str, selection_results: dict[str, bool]
    ) -> bool:
        """Evaluate the condition expression."""
        condition = condition.strip()

        if condition in selection_results:
            return selection_results[condition]

        if " and " in condition:
            parts = condition.split(" and ")
            return all(
                self._evaluate_condition(p.strip(), selection_results)
                for p in parts
            )

        if " or " in condition:
            parts = condition.split(" or ")
            return any(
                self._evaluate_condition(p.strip(), selection_results)
                for p in parts
            )

        if condition.startswith("not "):
            inner = condition[4:].strip()
            return not self._evaluate_condition(inner, selection_results)

        if condition.startswith("(") and condition.endswith(")"):
            return self._evaluate_condition(
                condition[1:-1].strip(), selection_results
            )

        match = re.match(r"(\d+) of (\w+)\*", condition)
        if match:
            count = int(match.group(1))
            prefix = match.group(2)
            matching = sum(
                1 for k, v in selection_results.items()
                if k.startswith(prefix) and v
            )
            return matching >= count

        if condition == "all of them":
            return all(selection_results.values())

        if condition == "1 of them":
            return any(selection_results.values())

        match = re.match(r"(\d+) of them", condition)
        if match:
            count = int(match.group(1))
            return sum(selection_results.values()) >= count

        return selection_results.get(condition, False)

    @property
    def rule_count(self) -> int:
        """Get number of loaded rules."""
        return len(self._rules)

    def get_rules_summary(self) -> dict[str, int]:
        """Get summary of rules by level."""
        summary = {"critical": 0, "high": 0, "medium": 0, "low": 0, "informational": 0}
        for rule in self._rules.values():
            level = rule.level.lower()
            if level in summary:
                summary[level] += 1
        return summary
