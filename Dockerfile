FROM python:3.12-slim

# Install git for remote scanning
RUN apt-get update && apt-get install -y --no-install-recommends git \
    && rm -rf /var/lib/apt/lists/*

# Install prism-scanner
COPY . /opt/prism-scanner
RUN pip install --no-cache-dir /opt/prism-scanner

# Working directory for mounted volumes
WORKDIR /workspace

ENTRYPOINT ["prism"]
CMD ["--help"]
