FROM python:3.11-slim

WORKDIR /workspace

# Install git and basic build utilities needed for Python packages
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Pre-install pytest so test suites can execute immediately
RUN pip install --no-cache-dir pytest

CMD ["/bin/bash"]
