FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    BANOSS_HOST=0.0.0.0 \
    BANOSS_PORT=9000 \
    BANOSS_DATA_DIR=/app/data

WORKDIR /app

RUN pip install --no-cache-dir uv

COPY pyproject.toml README.md ./
COPY banoss ./banoss

RUN uv pip install --system --no-cache .

VOLUME ["/app/data"]
EXPOSE 9000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:9000/healthz', timeout=3)" || exit 1

CMD ["banoss"]
