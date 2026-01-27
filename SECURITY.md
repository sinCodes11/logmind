# Security Policy

## Reporting Security Vulnerabilities

If you discover a security vulnerability in LogMind, please report it to:
- Email: security@example.com (replace with actual contact)
- Do NOT open public GitHub issues for security vulnerabilities

## Security Features

### 1. Secrets Management
- **Environment Variables**: All sensitive credentials (API keys, passwords) are loaded from environment variables
- **Pydantic SecretStr**: Passwords and API keys use `SecretStr` to prevent accidental logging
- **No Hardcoded Secrets**: No credentials are committed to the repository
- **.gitignore**: Properly configured to exclude `.env`, `.key`, and credential files

### 2. Input Validation
- **Log Line Length Limits**: Maximum 64KB per log line to prevent memory exhaustion
- **Message Length Limits**: Maximum 32KB per message field
- **File Size Limits**: Maximum 100MB per ingested file
- **Batch Size Limits**: Maximum 100K lines per batch operation
- **Port Validation**: Ports validated to be 0-65535
- **PID Validation**: Process IDs validated to be positive integers

### 3. Network Security
- **Localhost Binding**: Docker services bind to 127.0.0.1 by default (not 0.0.0.0)
- **Redis Authentication**: Redis requires password authentication
- **PostgreSQL SCRAM-SHA-256**: Modern password hashing for database
- **Request Timeouts**: All external HTTP requests have 10-60s timeouts
- **No Redirects**: Slack webhook calls disable redirects to prevent SSRF

### 4. Rate Limiting
- **LLM API Calls**: 50 calls/minute, 100K tokens/minute by default
- **Token Budget Control**: Prevents cost overruns from excessive API usage
- **Configurable Limits**: Rate limits can be adjusted per deployment

### 5. Path Traversal Protection
- **Path Resolution**: All file paths are resolved with `.resolve(strict=True)`
- **File Type Validation**: Ensures paths point to regular files, not symlinks or directories
- **Size Checks**: File sizes validated before reading

### 6. Docker Security
- **Non-Root User**: Application runs as non-root user (UID 1000)
- **Read-Only Volumes**: Data volumes mounted read-only where possible
- **Capability Dropping**: Unnecessary Linux capabilities dropped
- **No New Privileges**: `no-new-privileges` security option enabled
- **Resource Limits**: Redis has memory limits (256MB with LRU eviction)

### 7. Database Security
- **SQLAlchemy ORM**: All queries use parameterized ORM to prevent SQL injection
- **No Raw SQL**: No raw SQL queries with string interpolation
- **Connection Pooling**: Limited connection pool size (5 base, 10 overflow)
- **Prepared Statements**: All queries use prepared statements

### 8. Dependency Security
- **Pinned Versions**: Dependencies use minimum version constraints
- **Regular Updates**: Dependencies should be updated regularly
- **Vulnerability Scanning**: Use `pip-audit` or `safety` to scan dependencies

## Security Best Practices

### Production Deployment

1. **Change Default Passwords**
   ```bash
   # Generate strong passwords
   openssl rand -base64 32  # For Redis
   openssl rand -base64 32  # For PostgreSQL
   ```

2. **Use TLS/SSL**
   - Enable Redis TLS: `--tls-port 6380 --tls-cert-file /path/to/cert.pem`
   - Enable PostgreSQL SSL: `sslmode=require` in connection string
   - Use HTTPS for Slack webhooks (already enforced)

3. **Network Isolation**
   - Run services in a private network
   - Use firewall rules to restrict access
   - Consider using Docker networks with `internal: true`

4. **Monitoring & Logging**
   - Monitor failed authentication attempts
   - Log all API calls with rate limit violations
   - Alert on unusual patterns (excessive errors, high token usage)

5. **API Key Rotation**
   - Rotate Anthropic/OCI API keys regularly (every 90 days)
   - Rotate Slack webhook URLs if compromised
   - Update database passwords periodically

6. **Least Privilege**
   - Database user should only have necessary permissions
   - Redis user should not have admin commands enabled
   - Container user should not have sudo access

### Environment Variables Security

**Required for Production:**
```bash
# Strong passwords (minimum 16 characters)
REDIS_PASSWORD=<strong-random-password>
POSTGRES_PASSWORD=<strong-random-password>

# API Keys (keep secret)
ANTHROPIC_API_KEY=<your-key>
SLACK_WEBHOOK_URL=<your-webhook>

# Disable debug mode
DEBUG=false
LOG_LEVEL=INFO
```

### Known Limitations

1. **No Authentication Layer**: LogMind does not include built-in authentication. Deploy behind a reverse proxy with auth if exposing externally.

2. **No Encryption at Rest**: Logs are stored unencrypted in PostgreSQL. Use PostgreSQL encryption features if needed.

3. **LLM Prompt Injection**: User-controlled log data is sent to LLMs. Malicious log entries could attempt prompt injection.

4. **Resource Exhaustion**: Very high log volumes could exhaust memory/disk. Implement external rate limiting.

## Security Checklist

Before deploying to production:

- [ ] Changed all default passwords
- [ ] Configured strong Redis password
- [ ] Configured strong PostgreSQL password
- [ ] API keys stored in environment variables only
- [ ] `.env` file is in `.gitignore`
- [ ] Services bound to localhost or private network
- [ ] TLS/SSL enabled for external connections
- [ ] Rate limiting configured appropriately
- [ ] File size limits configured for your use case
- [ ] Monitoring and alerting configured
- [ ] Regular security updates scheduled
- [ ] Backup strategy implemented
- [ ] Incident response plan documented

## Updates

This security policy was last updated: 2026-01-27

For questions or concerns, contact the security team.

