"""LLM-based log analyzer orchestrator."""

from typing import Sequence

from logmind.config.settings import get_settings
from logmind.detection.detector import DetectionResult
from logmind.ingestion.base import NormalizedLog
from logmind.llm.base import BaseLLMProvider, LLMResponse
from logmind.llm.claude_provider import ClaudeProvider
from logmind.llm.oci_provider import OCIGenAIProvider
from logmind.llm.prompts import (
    ANOMALY_EXPLANATION_PROMPT,
    INCIDENT_SUMMARY_PROMPT,
    LOG_ANALYSIS_PROMPT,
    SECURITY_ANALYST_SYSTEM_PROMPT,
    format_detections_for_prompt,
    format_logs_for_prompt,
)


class LogAnalyzer:
    """
    Orchestrates LLM-based security log analysis.

    Supports multiple LLM providers with automatic fallback.
    """

    def __init__(
        self,
        provider: str | None = None,
        fallback_enabled: bool = True,
    ) -> None:
        """
        Initialize the log analyzer.

        Args:
            provider: LLM provider to use ("claude" or "oci")
            fallback_enabled: Enable fallback to other provider on failure
        """
        settings = get_settings()
        self._provider_name = provider or settings.llm_provider
        self._fallback_enabled = fallback_enabled
        self._primary_provider: BaseLLMProvider | None = None
        self._fallback_provider: BaseLLMProvider | None = None

        self._init_providers()

    def _init_providers(self) -> None:
        """Initialize LLM providers based on configuration."""
        if self._provider_name == "claude":
            self._primary_provider = ClaudeProvider()
            if self._fallback_enabled:
                self._fallback_provider = OCIGenAIProvider()
        else:
            self._primary_provider = OCIGenAIProvider()
            if self._fallback_enabled:
                self._fallback_provider = ClaudeProvider()

    def _get_provider(self) -> BaseLLMProvider:
        """Get an available provider."""
        if self._primary_provider and self._primary_provider.is_available():
            return self._primary_provider

        if self._fallback_provider and self._fallback_provider.is_available():
            return self._fallback_provider

        raise RuntimeError("No LLM provider available. Check API keys and configuration.")

    def analyze_logs(
        self,
        logs: Sequence[NormalizedLog],
        detections: Sequence[DetectionResult] | None = None,
        max_tokens: int = 4096,
    ) -> LLMResponse:
        """
        Analyze logs for security threats.

        Args:
            logs: Logs to analyze
            detections: Optional detection results for context
            max_tokens: Maximum response tokens

        Returns:
            LLMResponse with analysis
        """
        provider = self._get_provider()

        logs_text = format_logs_for_prompt(list(logs))
        detection_context = "No prior detections"
        if detections:
            detection_context = format_detections_for_prompt(list(detections))

        prompt = LOG_ANALYSIS_PROMPT.format(
            logs=logs_text,
            detection_context=detection_context,
        )

        return provider.generate(
            prompt=prompt,
            system_prompt=SECURITY_ANALYST_SYSTEM_PROMPT,
            max_tokens=max_tokens,
        )

    def generate_incident_summary(
        self,
        detections: Sequence[DetectionResult],
        logs: Sequence[NormalizedLog],
        max_tokens: int = 4096,
    ) -> LLMResponse:
        """
        Generate an incident summary report.

        Args:
            detections: Detection results to summarize
            logs: Related log entries
            max_tokens: Maximum response tokens

        Returns:
            LLMResponse with incident summary
        """
        provider = self._get_provider()

        detections_text = format_detections_for_prompt(list(detections))
        logs_text = format_logs_for_prompt(list(logs))

        prompt = INCIDENT_SUMMARY_PROMPT.format(
            detections=detections_text,
            logs=logs_text,
        )

        return provider.generate(
            prompt=prompt,
            system_prompt=SECURITY_ANALYST_SYSTEM_PROMPT,
            max_tokens=max_tokens,
        )

    def explain_anomalies(
        self,
        anomalies: list,
        logs: Sequence[NormalizedLog],
        max_tokens: int = 2048,
    ) -> LLMResponse:
        """
        Explain detected anomalies.

        Args:
            anomalies: Anomaly detection results
            logs: Related log entries
            max_tokens: Maximum response tokens

        Returns:
            LLMResponse with anomaly explanations
        """
        provider = self._get_provider()

        anomalies_text = []
        for anomaly in anomalies:
            if hasattr(anomaly, "description"):
                anomalies_text.append(f"- {anomaly.anomaly_type}: {anomaly.description}")
            else:
                anomalies_text.append(f"- {anomaly}")

        logs_text = format_logs_for_prompt(list(logs))

        prompt = ANOMALY_EXPLANATION_PROMPT.format(
            anomalies="\n".join(anomalies_text),
            logs=logs_text,
        )

        return provider.generate(
            prompt=prompt,
            system_prompt=SECURITY_ANALYST_SYSTEM_PROMPT,
            max_tokens=max_tokens,
        )

    def custom_analysis(
        self,
        prompt: str,
        logs: Sequence[NormalizedLog] | None = None,
        max_tokens: int = 4096,
    ) -> LLMResponse:
        """
        Run a custom analysis prompt.

        Args:
            prompt: Custom analysis prompt
            logs: Optional logs to include
            max_tokens: Maximum response tokens

        Returns:
            LLMResponse with analysis
        """
        provider = self._get_provider()

        full_prompt = prompt
        if logs:
            logs_text = format_logs_for_prompt(list(logs))
            full_prompt = f"{prompt}\n\n## Logs\n```\n{logs_text}\n```"

        return provider.generate(
            prompt=full_prompt,
            system_prompt=SECURITY_ANALYST_SYSTEM_PROMPT,
            max_tokens=max_tokens,
        )

    @property
    def active_provider(self) -> str:
        """Get the name of the currently active provider."""
        try:
            provider = self._get_provider()
            return provider.provider_name
        except RuntimeError:
            return "none"

    def is_available(self) -> bool:
        """Check if any LLM provider is available."""
        try:
            self._get_provider()
            return True
        except RuntimeError:
            return False
