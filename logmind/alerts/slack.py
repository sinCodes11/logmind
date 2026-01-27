"""Slack webhook alerting."""

import json
from dataclasses import dataclass
from datetime import datetime

import requests

from logmind.config.settings import get_settings
from logmind.detection.detector import DetectionResult


@dataclass
class AlertResult:
    """Result of sending an alert."""

    success: bool
    message: str
    timestamp: datetime


class SlackAlerter:
    """
    Slack webhook alerter for security notifications.

    Sends formatted alerts to Slack channels via webhook.
    """

    SEVERITY_COLORS = {
        "critical": "#FF0000",
        "high": "#FF6600",
        "medium": "#FFCC00",
        "low": "#00CC00",
        "informational": "#0066FF",
    }

    SEVERITY_EMOJI = {
        "critical": ":rotating_light:",
        "high": ":warning:",
        "medium": ":large_yellow_circle:",
        "low": ":large_green_circle:",
        "informational": ":information_source:",
    }

    def __init__(
        self,
        webhook_url: str | None = None,
        channel: str | None = None,
    ) -> None:
        """
        Initialize Slack alerter.

        Args:
            webhook_url: Slack webhook URL
            channel: Channel to post to (optional, uses webhook default)
        """
        settings = get_settings()

        self._webhook_url = webhook_url
        if not self._webhook_url and settings.slack_webhook_url:
            self._webhook_url = settings.slack_webhook_url.get_secret_value()

        self._channel = channel or settings.slack_channel

    def send_detection_alert(
        self,
        detection: DetectionResult,
        include_details: bool = True,
    ) -> AlertResult:
        """
        Send an alert for a detection result.

        Args:
            detection: DetectionResult to alert on
            include_details: Include detailed findings

        Returns:
            AlertResult with status
        """
        if not self._webhook_url:
            return AlertResult(
                success=False,
                message="Slack webhook URL not configured",
                timestamp=datetime.utcnow(),
            )

        severity = detection.max_severity
        emoji = self.SEVERITY_EMOJI.get(severity, ":question:")
        color = self.SEVERITY_COLORS.get(severity, "#808080")

        title = f"{emoji} Security Detection - {severity.upper()}"

        fields = [
            {
                "title": "Source",
                "value": detection.source,
                "short": True,
            },
            {
                "title": "Timestamp",
                "value": detection.log_timestamp,
                "short": True,
            },
        ]

        if detection.mitre_tactics:
            fields.append({
                "title": "MITRE Tactics",
                "value": ", ".join(detection.mitre_tactics),
                "short": True,
            })

        if detection.mitre_techniques:
            fields.append({
                "title": "MITRE Techniques",
                "value": ", ".join(detection.mitre_techniques),
                "short": True,
            })

        if include_details:
            details = []
            for match in detection.sigma_matches:
                details.append(f"• *Sigma*: {match.rule_name} ({match.level})")
            for anomaly in detection.anomalies:
                details.append(f"• *Anomaly*: {anomaly.description}")

            if details:
                fields.append({
                    "title": "Detections",
                    "value": "\n".join(details),
                    "short": False,
                })

        payload = {
            "attachments": [
                {
                    "color": color,
                    "title": title,
                    "fields": fields,
                    "footer": "LogMind Security Analyzer",
                    "ts": int(datetime.utcnow().timestamp()),
                }
            ]
        }

        if self._channel:
            payload["channel"] = self._channel

        return self._send_payload(payload)

    def send_incident_alert(
        self,
        incident_id: str,
        title: str,
        severity: str,
        summary: str,
        affected_systems: list[str] | None = None,
        recommendations: list[str] | None = None,
    ) -> AlertResult:
        """
        Send an incident alert.

        Args:
            incident_id: Incident identifier
            title: Incident title
            severity: Severity level
            summary: Incident summary
            affected_systems: List of affected systems
            recommendations: List of recommended actions

        Returns:
            AlertResult with status
        """
        if not self._webhook_url:
            return AlertResult(
                success=False,
                message="Slack webhook URL not configured",
                timestamp=datetime.utcnow(),
            )

        emoji = self.SEVERITY_EMOJI.get(severity.lower(), ":question:")
        color = self.SEVERITY_COLORS.get(severity.lower(), "#808080")

        blocks = [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": f"{emoji} Security Incident: {title}",
                },
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Incident ID:*\n{incident_id}"},
                    {"type": "mrkdwn", "text": f"*Severity:*\n{severity.upper()}"},
                ],
            },
            {
                "type": "section",
                "text": {"type": "mrkdwn", "text": f"*Summary:*\n{summary}"},
            },
        ]

        if affected_systems:
            blocks.append({
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*Affected Systems:*\n• " + "\n• ".join(affected_systems),
                },
            })

        if recommendations:
            blocks.append({
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*Recommendations:*\n• " + "\n• ".join(recommendations),
                },
            })

        blocks.append({"type": "divider"})

        payload = {
            "attachments": [{"color": color, "blocks": blocks}],
        }

        if self._channel:
            payload["channel"] = self._channel

        return self._send_payload(payload)

    def send_test_message(self) -> AlertResult:
        """Send a test message to verify webhook configuration."""
        payload = {
            "text": ":white_check_mark: LogMind Slack integration test successful!",
            "attachments": [
                {
                    "color": "#00CC00",
                    "text": "Your Slack webhook is configured correctly.",
                    "footer": "LogMind Security Analyzer",
                }
            ],
        }

        if self._channel:
            payload["channel"] = self._channel

        return self._send_payload(payload)

    def _send_payload(self, payload: dict) -> AlertResult:
        """Send payload to Slack webhook with security controls."""
        if not self._webhook_url:
            return AlertResult(
                success=False,
                message="Webhook URL not configured",
                timestamp=datetime.utcnow(),
            )

        # Validate payload size to prevent abuse
        payload_str = json.dumps(payload)
        if len(payload_str) > 50000:  # 50KB max
            return AlertResult(
                success=False,
                message="Payload too large (max 50KB)",
                timestamp=datetime.utcnow(),
            )

        try:
            response = requests.post(
                self._webhook_url,
                data=payload_str,
                headers={
                    "Content-Type": "application/json",
                    "User-Agent": "LogMind-Security-Analyzer/1.0",
                },
                timeout=10,
                allow_redirects=False,  # Prevent redirect attacks
            )

            if response.status_code == 200:
                return AlertResult(
                    success=True,
                    message="Alert sent successfully",
                    timestamp=datetime.utcnow(),
                )
            else:
                # Limit error message length
                error_text = response.text[:500] if response.text else "Unknown error"
                return AlertResult(
                    success=False,
                    message=f"Slack API error: {response.status_code} - {error_text}",
                    timestamp=datetime.utcnow(),
                )

        except requests.Timeout:
            return AlertResult(
                success=False,
                message="Request timeout (10s)",
                timestamp=datetime.utcnow(),
            )
        except requests.RequestException as e:
            return AlertResult(
                success=False,
                message=f"Request failed: {str(e)[:200]}",
                timestamp=datetime.utcnow(),
            )

    def is_configured(self) -> bool:
        """Check if Slack alerting is configured."""
        return bool(self._webhook_url)
