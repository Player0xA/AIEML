# Dockerfile for emltriage
FROM python:3.11-slim

# Install system dependencies
RUN apt-get update && apt-get install -y \
    git \
    libmagic1 \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy requirements first for better caching
COPY requirements.txt requirements-ai.txt ./

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt
RUN pip install --no-cache-dir -r requirements-ai.txt

# Copy the application
COPY . .

# Install emltriage
RUN pip install -e .

# Create directories for outputs
RUN mkdir -p /data/output /data/watchlists

# Set environment variables
ENV PYTHONUNBUFFERED=1
ENV EMLTRIAGE_AI_PROVIDER=ollama

# Default command
ENTRYPOINT ["emltriage"]
CMD ["--help"]
