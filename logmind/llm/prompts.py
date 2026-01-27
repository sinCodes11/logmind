"""Prompt templates for LLM-based log analysis."""

SECURITY_ANALYST_SYSTEM_PROMPT = """You are an expert security analyst specializing in log analysis and threat detection. Your role is to:

1. Analyze security logs for indicators of compromise (IOCs)
2. Identify attack patterns and techniques
3. Map findings to MITRE ATT&CK framework
4. Provide actionable recommendations
5. Assess severity and urgency

Be concise, technical, and actionable in your analysis. Focus on facts from the logs rather than speculation. When uncertain, indicate confidence level."""


LOG_ANALYSIS_PROMPT = """Analyze the following security logs for potential threats and anomalies.

## Logs
```
{logs}
```

## Detection Context
{detection_context}

## Analysis Required
1. **Threat Assessment**: What security threats or suspicious activities are present?
2. **Attack Classification**: What type of attack is this (if applicable)?
3. **MITRE ATT&CK Mapping**: Which tactics and techniques are involved?
4. **Severity Rating**: Critical/High/Medium/Low with justification
5. **Affected Assets**: Which systems, users, or resources are impacted?
6. **Recommendations**: What immediate actions should be taken?

Provide your analysis in a structured format."""


INCIDENT_SUMMARY_PROMPT = """Generate a security incident summary based on the following detections and logs.

## Detections
{detections}

## Related Logs
```
{logs}
```

## Required Output
Create a concise incident report with:

1. **Incident Title**: Brief descriptive title
2. **Executive Summary**: 2-3 sentence overview for management
3. **Technical Details**: Key findings from log analysis
4. **Timeline**: Sequence of events with timestamps
5. **MITRE ATT&CK Mapping**: Relevant tactics and techniques
6. **Impact Assessment**: Systems, data, and users affected
7. **Severity**: Critical/High/Medium/Low with reasoning
8. **Recommendations**: Prioritized response actions

Format the output as a professional incident report."""


THREAT_INTEL_PROMPT = """Analyze these indicators for threat intelligence context.

## Indicators
{indicators}

## Log Context
```
{logs}
```

## Required Analysis
1. **Indicator Classification**: What type of threat indicators are present?
2. **Known Threat Associations**: Any matches to known threat actors or campaigns?
3. **Behavioral Analysis**: What does the activity pattern suggest?
4. **Risk Assessment**: What is the potential impact?
5. **Hunting Recommendations**: What additional indicators should we look for?

Provide factual analysis based on the data provided."""


ANOMALY_EXPLANATION_PROMPT = """Explain the following anomalies detected in security logs.

## Anomalies
{anomalies}

## Supporting Logs
```
{logs}
```

## Required Output
For each anomaly:
1. **What Happened**: Clear explanation of the anomalous activity
2. **Why It's Suspicious**: Security implications
3. **Possible Causes**: Both malicious and benign explanations
4. **Investigation Steps**: How to determine if this is a real threat
5. **Recommended Actions**: What to do if confirmed malicious

Be balanced - consider both true positive and false positive scenarios."""


def format_logs_for_prompt(logs: list, max_logs: int = 50) -> str:
    """Format logs for inclusion in prompts."""
    if len(logs) > max_logs:
        logs = logs[:max_logs]

    formatted = []
    for log in logs:
        if hasattr(log, "raw"):
            formatted.append(log.raw)
        elif isinstance(log, dict):
            formatted.append(log.get("raw", str(log)))
        else:
            formatted.append(str(log))

    return "\n".join(formatted)


def format_detections_for_prompt(detections: list) -> str:
    """Format detection results for inclusion in prompts."""
    formatted = []

    for detection in detections:
        if hasattr(detection, "sigma_matches"):
            for match in detection.sigma_matches:
                formatted.append(
                    f"- Sigma Rule: {match.rule_name} (Level: {match.level})"
                )
                if match.mitre_techniques:
                    formatted.append(f"  MITRE: {', '.join(match.mitre_techniques)}")

        if hasattr(detection, "anomalies"):
            for anomaly in detection.anomalies:
                formatted.append(
                    f"- Anomaly: {anomaly.anomaly_type} (Severity: {anomaly.severity})"
                )
                formatted.append(f"  Description: {anomaly.description}")

    return "\n".join(formatted) if formatted else "No specific detections"
