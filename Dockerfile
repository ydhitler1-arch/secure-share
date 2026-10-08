FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    DATA_DIR=/data

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt "gunicorn>=22"

COPY app.py ./
COPY static ./static
COPY templates ./templates

# Run as an unprivileged user; /data holds the database, encrypted files and session key.
RUN useradd --system --uid 10001 --no-create-home app \
    && mkdir /data && chown app /data
USER app
VOLUME /data
EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request as u; u.urlopen('http://127.0.0.1:8000/healthz', timeout=3)" || exit 1

# One worker with threads: rate limits are kept in memory, so extra worker processes would each
# get their own counters. Scale with threads, or move the limiter to Redis before adding workers.
CMD ["gunicorn", "--bind", "0.0.0.0:8000", "--workers", "1", "--threads", "8", \
     "--timeout", "60", "--access-logfile", "-", "app:app"]
