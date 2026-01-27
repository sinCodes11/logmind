"""LogMind CLI interface."""

import asyncio
import sys
from pathlib import Path

import click
import structlog

from logmind import __version__


def setup_logging(level: str = "INFO") -> None:
    """Configure structured logging."""
    structlog.configure(
        processors=[
            structlog.stdlib.filter_by_level,
            structlog.stdlib.add_logger_name,
            structlog.stdlib.add_log_level,
            structlog.stdlib.PositionalArgumentsFormatter(),
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            structlog.dev.ConsoleRenderer(colors=True),
        ],
        wrapper_class=structlog.stdlib.BoundLogger,
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
        cache_logger_on_first_use=True,
    )


@click.group()
@click.version_option(version=__version__)
@click.option("--debug", is_flag=True, help="Enable debug logging")
@click.pass_context
def cli(ctx: click.Context, debug: bool) -> None:
    """LogMind - LLM-Powered Security Log Analyzer."""
    ctx.ensure_object(dict)
    ctx.obj["debug"] = debug
    setup_logging("DEBUG" if debug else "INFO")


@cli.command()
@click.pass_context
def run(ctx: click.Context) -> None:
    """Start the full LogMind pipeline."""
    from logmind.config.settings import get_settings

    settings = get_settings()
    click.echo(f"Starting LogMind v{__version__}")
    click.echo(f"LLM Provider: {settings.llm_provider}")
    click.echo(f"Redis: {settings.redis_host}:{settings.redis_port}")
    click.echo(f"PostgreSQL: {settings.postgres_host}:{settings.postgres_port}")

    click.echo("\nInitializing components...")

    try:
        from logmind.detection import DetectionOrchestrator
        detector = DetectionOrchestrator(settings.sigma_rules_path)
        click.echo(f"  Sigma rules loaded: {detector.get_stats()['sigma_rules_loaded']}")
    except Exception as e:
        click.echo(f"  Detection engine: Error - {e}", err=True)

    try:
        from logmind.llm import LogAnalyzer
        analyzer = LogAnalyzer()
        click.echo(f"  LLM provider: {analyzer.active_provider}")
    except Exception as e:
        click.echo(f"  LLM provider: Error - {e}", err=True)

    click.echo("\nLogMind ready. Use Ctrl+C to stop.")
    click.echo("Run 'logmind worker' to start processing logs.")


@cli.command()
@click.pass_context
def worker(ctx: click.Context) -> None:
    """Start the log processing worker."""
    click.echo("Starting LogMind worker...")

    async def run_worker():
        from logmind.config.settings import get_settings
        from logmind.detection import DetectionOrchestrator
        from logmind.queue import LogConsumer

        settings = get_settings()
        detector = DetectionOrchestrator(settings.sigma_rules_path)
        consumer = LogConsumer()

        click.echo(f"Listening on stream: {settings.redis_stream_name}")

        async for message_id, log in consumer.consume():
            detections = detector.detect(log)
            if detections.has_detections:
                click.echo(
                    f"[{log.timestamp}] Detection: {detections.max_severity} "
                    f"from {log.source}"
                )
            await consumer.acknowledge(message_id)

    try:
        asyncio.run(run_worker())
    except KeyboardInterrupt:
        click.echo("\nWorker stopped.")


@cli.command("init-db")
@click.option("--drop", is_flag=True, help="Drop existing tables first")
@click.pass_context
def init_db(ctx: click.Context, drop: bool) -> None:
    """Initialize the database schema."""
    from logmind.database import get_db

    db = get_db()

    if drop:
        click.echo("Dropping existing tables...")
        db.drop_tables()

    click.echo("Creating database tables...")
    db.create_tables()
    click.echo("Database initialized successfully.")


@cli.command("load-rules")
@click.option("--path", default="rules", help="Path to Sigma rules directory")
@click.pass_context
def load_rules(ctx: click.Context, path: str) -> None:
    """Load and validate Sigma rules."""
    from logmind.detection.sigma import SigmaEngine

    click.echo(f"Loading rules from: {path}")

    engine = SigmaEngine(path)
    count = engine.load_rules()

    click.echo(f"Loaded {count} rules.")

    summary = engine.get_rules_summary()
    for level, num in summary.items():
        if num > 0:
            click.echo(f"  {level}: {num}")


@cli.command()
@click.argument("file", type=click.Path(exists=True))
@click.option(
    "--format",
    "log_format",
    type=click.Choice(["syslog", "json", "cef", "auto"]),
    default="auto",
    help="Log format",
)
@click.option("--detect/--no-detect", default=True, help="Run detection on logs")
@click.option("--publish/--no-publish", default=False, help="Publish to Redis queue")
@click.pass_context
def ingest(
    ctx: click.Context,
    file: str,
    log_format: str,
    detect: bool,
    publish: bool,
) -> None:
    """Ingest a log file."""
    from logmind.ingestion import SyslogParser, JSONLogParser, CEFParser
    from logmind.detection import DetectionOrchestrator

    file_path = Path(file).resolve()

    # Security: Validate file path to prevent path traversal
    try:
        file_path = file_path.resolve(strict=True)
        # Ensure file is a regular file, not a symlink to sensitive location
        if not file_path.is_file():
            click.echo(f"Error: {file} is not a regular file", err=True)
            sys.exit(1)
    except (OSError, RuntimeError) as e:
        click.echo(f"Error: Invalid file path - {e}", err=True)
        sys.exit(1)

    click.echo(f"Ingesting: {file_path.name}")

    if log_format == "auto":
        suffix = file_path.suffix.lower()
        if suffix == ".json":
            log_format = "json"
        elif "cef" in file_path.name.lower():
            log_format = "cef"
        else:
            log_format = "syslog"
        click.echo(f"Auto-detected format: {log_format}")

    parser_map = {
        "syslog": SyslogParser(),
        "json": JSONLogParser(),
        "cef": CEFParser(),
    }
    parser = parser_map[log_format]

    # Security: Limit file size to prevent DoS
    max_file_size = 100 * 1024 * 1024  # 100MB
    if file_path.stat().st_size > max_file_size:
        click.echo(f"Error: File too large (max {max_file_size // 1024 // 1024}MB)", err=True)
        sys.exit(1)

    with open(file_path, "r", encoding="utf-8", errors="replace") as f:
        lines = f.readlines()

    logs = parser.parse_batch(lines, source=file_path.name)
    click.echo(f"Parsed {len(logs)} log entries.")

    if detect and logs:
        detector = DetectionOrchestrator()
        results = detector.detect_batch(logs)
        click.echo(f"Detections: {len(results)}")

        for result in results[:10]:
            click.echo(
                f"  [{result.max_severity}] {result.source} - "
                f"Sigma: {len(result.sigma_matches)}, "
                f"Anomaly: {len(result.anomalies)}"
            )

        if len(results) > 10:
            click.echo(f"  ... and {len(results) - 10} more")

    if publish and logs:
        from logmind.queue import LogProducer
        producer = LogProducer()
        ids = producer.publish_batch(logs)
        click.echo(f"Published {len(ids)} logs to queue.")


@cli.command()
@click.option("--hours", default=1, help="Hours of logs to analyze")
@click.option("--output", type=click.Path(), help="Output file for report")
@click.pass_context
def analyze(ctx: click.Context, hours: int, output: str | None) -> None:
    """Run LLM analysis on recent logs."""
    from logmind.llm import LogAnalyzer
    from logmind.database import get_db, LogRepository

    click.echo(f"Analyzing logs from last {hours} hour(s)...")

    analyzer = LogAnalyzer()
    if not analyzer.is_available():
        click.echo("Error: No LLM provider available.", err=True)
        sys.exit(1)

    click.echo(f"Using LLM provider: {analyzer.active_provider}")

    db = get_db()
    with db.session() as session:
        repo = LogRepository(session)
        logs = repo.get_recent_logs(hours=hours)

    if not logs:
        click.echo("No logs found in the specified time range.")
        return

    click.echo(f"Found {len(logs)} logs. Running analysis...")

    normalized_logs = []
    for entry in logs:
        from logmind.ingestion.base import NormalizedLog, LogSeverity
        normalized_logs.append(NormalizedLog(
            id=entry.log_id,
            timestamp=entry.timestamp,
            source=entry.source,
            source_type=entry.source_type,
            severity=LogSeverity(entry.severity.value if hasattr(entry.severity, 'value') else entry.severity),
            message=entry.message,
            raw=entry.raw,
            src_ip=entry.src_ip,
            user=entry.user,
        ))

    response = analyzer.analyze_logs(normalized_logs[:50])

    if output:
        with open(output, "w") as f:
            f.write(response.content)
        click.echo(f"Analysis saved to: {output}")
    else:
        click.echo("\n" + "=" * 60)
        click.echo(response.content)
        click.echo("=" * 60)

    click.echo(f"\nTokens used: {response.total_tokens}")


@cli.command()
@click.option("--status", type=click.Choice(["open", "all"]), default="open")
@click.option("--limit", default=20, help="Maximum incidents to show")
@click.pass_context
def incidents(ctx: click.Context, status: str, limit: int) -> None:
    """List security incidents."""
    from logmind.database import get_db
    from logmind.database.repository import IncidentRepository

    db = get_db()
    with db.session() as session:
        repo = IncidentRepository(session)

        if status == "open":
            items = repo.get_open_incidents()
        else:
            items = repo.get_all_incidents()

    if not items:
        click.echo("No incidents found.")
        return

    click.echo(f"{'ID':<36} {'Severity':<10} {'Status':<12} {'Title'}")
    click.echo("-" * 100)

    for incident in items[:limit]:
        click.echo(
            f"{incident.incident_id:<36} "
            f"{incident.severity:<10} "
            f"{incident.status:<12} "
            f"{incident.title[:40]}"
        )


@cli.command()
@click.pass_context
def status(ctx: click.Context) -> None:
    """Show LogMind system status."""
    from logmind.config.settings import get_settings

    settings = get_settings()

    click.echo(f"LogMind v{__version__}")
    click.echo("")

    click.echo("Configuration:")
    click.echo(f"  LLM Provider: {settings.llm_provider}")
    click.echo(f"  Redis: {settings.redis_host}:{settings.redis_port}")
    click.echo(f"  PostgreSQL: {settings.postgres_host}:{settings.postgres_port}")
    click.echo("")

    click.echo("Component Status:")

    try:
        from logmind.queue import RedisClient
        redis = RedisClient()
        if redis.ping():
            click.echo("  Redis: Connected")
        else:
            click.echo("  Redis: Disconnected")
    except Exception as e:
        click.echo(f"  Redis: Error - {e}")

    try:
        from logmind.database import get_db
        db = get_db()
        with db.session() as session:
            session.execute("SELECT 1")
        click.echo("  PostgreSQL: Connected")
    except Exception as e:
        click.echo(f"  PostgreSQL: Error - {e}")

    try:
        from logmind.llm import LogAnalyzer
        analyzer = LogAnalyzer()
        if analyzer.is_available():
            click.echo(f"  LLM ({analyzer.active_provider}): Available")
        else:
            click.echo("  LLM: Not configured")
    except Exception as e:
        click.echo(f"  LLM: Error - {e}")

    try:
        from logmind.detection.sigma import SigmaEngine
        engine = SigmaEngine(settings.sigma_rules_path)
        count = engine.load_rules()
        click.echo(f"  Sigma Rules: {count} loaded")
    except Exception as e:
        click.echo(f"  Sigma Rules: Error - {e}")

    try:
        from logmind.alerts import SlackAlerter
        alerter = SlackAlerter()
        if alerter.is_configured():
            click.echo("  Slack: Configured")
        else:
            click.echo("  Slack: Not configured")
    except Exception as e:
        click.echo(f"  Slack: Error - {e}")


@cli.command("test-slack")
@click.pass_context
def test_slack(ctx: click.Context) -> None:
    """Send a test message to Slack."""
    from logmind.alerts import SlackAlerter

    alerter = SlackAlerter()

    if not alerter.is_configured():
        click.echo("Error: Slack webhook URL not configured.", err=True)
        sys.exit(1)

    click.echo("Sending test message to Slack...")
    result = alerter.send_test_message()

    if result.success:
        click.echo("Test message sent successfully!")
    else:
        click.echo(f"Failed: {result.message}", err=True)
        sys.exit(1)


def main() -> None:
    """Entry point for the CLI."""
    cli()


if __name__ == "__main__":
    main()
