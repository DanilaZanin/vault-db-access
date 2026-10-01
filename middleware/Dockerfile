# ---- build stage: uv lives only here ----
FROM python:3.12-slim@sha256:f77ac9e44ae96ef2c90b8053ea08c31f8be030f824196b0ae4db6d462c84e51f AS build
ENV UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy UV_PROJECT_ENVIRONMENT=/opt/venv
RUN pip install --no-cache-dir uv==0.11.14
WORKDIR /app
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev --no-install-project

# ---- runtime stage: no uv, no pip-installed tooling, OS packages upgraded ----
FROM python:3.12-slim@sha256:f77ac9e44ae96ef2c90b8053ea08c31f8be030f824196b0ae4db6d462c84e51f
ENV PYTHONUNBUFFERED=1 PATH="/opt/venv/bin:$PATH"
RUN apt-get update && apt-get -y upgrade && apt-get clean && rm -rf /var/lib/apt/lists/* \
    && pip uninstall -y pip setuptools wheel 2>/dev/null; true
WORKDIR /app
COPY --from=build /opt/venv /opt/venv
COPY middleware/app ./app
# sha256 of the plugin baked into the vault image (used by `app.setup` to register it)
COPY --from=vaultimg /vault/plugins/clickhouse-database-plugin.sha256 /opt/vdba/clickhouse-plugin.sha256

RUN useradd --create-home --uid 1000 appuser && mkdir /data && chown appuser /data && chmod 700 /data
USER appuser

EXPOSE 8000
HEALTHCHECK --interval=10s --timeout=3s --start-period=10s \
    CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/healthz', timeout=2)"]

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--no-server-header"]
