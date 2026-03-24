# Base image: Python 3.13 slim for minimal footprint
FROM python:3.13-slim

# System dependencies:
#   docker.io       -- worker needs Docker socket to launch scan containers
#   libpango*       -- WeasyPrint PDF rendering (pango text layout engine)
#   libgdk-pixbuf*  -- WeasyPrint image handling
#   libcairo2       -- WeasyPrint vector graphics backend
#   libffi-dev      -- cffi build dependency for cryptography
RUN apt-get update && apt-get install -y --no-install-recommends \
    docker.io \
    libpango-1.0-0 libpangocairo-1.0-0 libpangoft2-1.0-0 \
    libgdk-pixbuf-2.0-0 libffi-dev libcairo2 \
    && rm -rf /var/lib/apt/lists/*

# uv: fast Python package installer (replaces pip)
COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

# Run as non-root for security
RUN groupadd -r pentest && useradd -r -g pentest -d /app -s /sbin/nologin pentest \
    && mkdir -p /app && chown pentest:pentest /app

USER pentest
WORKDIR /app

# Install Python dependencies (cached layer -- only rebuilds when deps change)
COPY --chown=pentest:pentest pyproject.toml uv.lock* README.md ./
RUN uv sync --no-dev --frozen 2>/dev/null || uv sync --no-dev

# Copy application source
COPY --chown=pentest:pentest . .

EXPOSE 8000

CMD ["uv", "run", "uvicorn", "src.api.app:app", "--host", "0.0.0.0", "--port", "8000"]
