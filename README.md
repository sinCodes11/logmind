# LogMind

<div align="center">
  <img src="assets/banner.svg" width="100%" />
</div>

<p align="center">
  <img src="https://img.shields.io/badge/python-3.11%2B-blue?style=flat-square" alt="Python">
  <img src="https://img.shields.io/badge/Claude_API-LLM-a855f7?style=flat-square" alt="Claude">
  <img src="https://img.shields.io/badge/license-MIT-green?style=flat-square" alt="License">
</p>

LLM-powered security log analyzer that combines rule-based detection (Sigma) with AI analysis to identify threats, map to MITRE ATT&CK, and generate actionable incident reports — in seconds, not hours.

## Overview

LogMind ingests logs from multiple sources, applies Sigma rules and statistical anomaly detection, enriches findings with MITRE ATT&CK context, and uses Claude or OCI GenAI to produce human-readable incident summaries.

**Key Capabilities:**
- Multi-format log ingestion (syslog RFC 3164/5424, JSON, CEF)
- Real-time processing with Redis Streams and consumer groups
- Sigma rules detection engine
- Statistical anomaly detection — brute force, port scans, off-hours activity
- Dual LLM support: Claude API + OCI Generative AI
- MITRE ATT&CK technique mapping
- Automated incident report generation
- Slack alerting integration

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              LogMind Pipeline                                │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌──────────┐    ┌──────────┐    ┌───────────────┐    ┌──────────────────┐ │
│  │  Syslog  │    │   JSON   │    │      CEF      │    │   File Watcher   │ │
│  │  Parser  │    │  Parser  │    │    Parser     │    │                  │ │
│  └────┬─────┘    └────┬─────┘    └───────┬───────┘    └────────┬─────────┘ │
│       └───────────────┴─────────┬────────┴──────────────────────┘          │
│                                 ▼                                          │
│                    ┌────────────────────────┐                              │
│                    │    Normalized Logs     │                              │
│                    └───────────┬────────────┘                              │
│                                ▼                                           │
│                    ┌────────────────────────┐                              │
│                    │     Redis Streams      │                              │
│                    └───────────┬────────────┘                              │
│           ┌────────────────────┼────────────────────┐                      │
│           ▼                    ▼                    ▼                      │
│  ┌────────────────┐  ┌────────────────┐  ┌────────────────┐               │
│  │  Sigma Rules   │  │    Anomaly     │  │  LLM Analysis  │               │
│  │    Engine      │  │   Detector     │  │  (Claude/OCI)  │               │
│  └───────┬────────┘  └───────┬────────┘  └───────┬────────┘               │
│          └───────────────────┴───────────────────┘                         │
│                              ▼                                             │
│                    ┌────────────────────────┐                              │
│                    │   Detection Results    │                              │
│                    └───────────┬────────────┘                              │
│           ┌────────────────────┼────────────────────┐                      │
│           ▼                    ▼                    ▼                      │
│  ┌────────────────┐  ┌────────────────┐  ┌────────────────┐               │
│  │  MITRE ATT&CK  │  │   Incident     │  │     Slack      │               │
│  │    Mapper      │  │   Generator    │  │    Alerter     │               │
│  └────────────────┘  └────────────────┘  └────────────────┘               │
│                                ▼                                           │
│                    ┌────────────────────────┐                              │
│                    │     PostgreSQL         │                              │
│                    │  (Logs, Detections,    │                              │
│                    │      Incidents)        │                              │
│                    └────────────────────────┘                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Quick Start

### Prerequisites

- Python 3.11+
- Docker and Docker Compose
- Anthropic API key or OCI GenAI access

### Installation

```bash
cd LogMind
python -m venv venv
source venv/bin/activate

pip install -r requirements.txt
pip install -e .

cp .env.example .env
# Edit .env with your API keys
```

### Start Infrastructure

```bash
docker-compose up -d redis postgres
logmind init-db
logmind load-rules
```

### Basic Usage

```bash
logmind status
logmind ingest data/samples/auth.log --format syslog
logmind analyze --hours 1
logmind incidents
logmind worker
```

## Configuration

```bash
# LLM Provider (claude or oci)
LLM_PROVIDER=claude
ANTHROPIC_API_KEY=your_api_key_here

# Or use OCI Generative AI
LLM_PROVIDER=oci
OCI_COMPARTMENT_ID=ocid1.compartment...

# Slack Alerting
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/...
```

### Sigma Rules

Rules live in `rules/` — `rules/linux/` for SSH/sudo, `rules/web/` for SQLi/XSS. Drop in any Sigma YAML to extend detection.

## CLI Reference

| Command | Description |
|---------|-------------|
| `logmind run` | Start full pipeline |
| `logmind worker` | Start processing worker |
| `logmind init-db` | Initialize database schema |
| `logmind load-rules` | Load Sigma rules |
| `logmind ingest <file>` | Ingest a log file |
| `logmind analyze` | Run LLM analysis |
| `logmind incidents` | List security incidents |
| `logmind status` | Show system status |
| `logmind test-slack` | Test Slack integration |

## Detection Capabilities

**Sigma rules detect:**
- SSH brute force, sudo privilege escalation, web shell activity
- SQL injection, path traversal, XSS

**Anomaly detection:**
- Brute force patterns (configurable threshold)
- Port scanning, off-hours sensitive operations, new external IP connections

**LLM analysis provides:**
- Threat classification + MITRE ATT&CK mapping
- Severity rating with justification
- Impact analysis and actionable recommendations

## Project Structure

```
LogMind/
├── logmind/
│   ├── cli.py              # Click CLI interface
│   ├── config/             # Pydantic settings
│   ├── ingestion/          # Log parsers (syslog, JSON, CEF)
│   ├── queue/              # Redis stream producer/consumer
│   ├── detection/          # Sigma engine + anomaly detection
│   ├── llm/                # LLM providers (Claude, OCI)
│   ├── mitre/              # ATT&CK data and mapping
│   ├── incidents/          # Incident generation
│   ├── alerts/             # Slack alerting
│   └── database/           # SQLAlchemy models
├── rules/                  # Sigma rules
├── data/samples/           # Sample log files
├── tests/                  # Unit and integration tests
├── docker-compose.yml
└── Dockerfile
```

## Testing

```bash
pytest
pytest --cov=logmind
pytest tests/unit/test_parsers.py
```

## Docker Deployment

```bash
docker-compose up -d
docker-compose logs -f logmind
docker-compose down
```

## Cost Estimates (OCI)

| Resource | Configuration | Monthly Cost |
|----------|---------------|--------------|
| Redis | VM.Standard.E4.Flex (1 OCPU) | ~$15 |
| PostgreSQL | DB System (1 OCPU) | ~$50 |
| OCI GenAI | Command-R+ (10K requests/day) | ~$30 |
| **Total** | | **~$95/month** |

*Claude API: ~$3/1M input tokens, ~$15/1M output tokens*

## Security

- API keys in environment variables — never committed
- Least-privilege database access
- Redis password auth supported
- Input validation on all parsers
- Rate limiting recommended for production LLM calls

## License

MIT — see LICENSE for details.

## Author

**Daniel Gregg Jr**
- Portfolio: [daniel-eportfolio.web.app](https://daniel-eportfolio.web.app)
- LinkedIn: [linkedin.com/in/daniel-sin-1881ske89](https://linkedin.com/in/daniel-sin-1881ske89)
