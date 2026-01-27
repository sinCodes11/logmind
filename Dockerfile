FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for layer caching
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY logmind/ ./logmind/
COPY rules/ ./rules/
COPY data/ ./data/
COPY config.yaml .

# Create non-root user
RUN useradd -m -u 1000 logmind && \
    chown -R logmind:logmind /app

USER logmind

# Set Python path
ENV PYTHONPATH=/app
ENV PYTHONUNBUFFERED=1

# Expose port for potential API
EXPOSE 8000

# Default command
ENTRYPOINT ["python", "-m", "logmind.cli"]
CMD ["run"]
