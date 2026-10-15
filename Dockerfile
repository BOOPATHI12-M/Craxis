# AI Phishing Guard backend (Flask API + model).
#
# Build:  docker build -t ai-phishing-guard .
# Run:    docker run --rm -p 127.0.0.1:5000:5000 ai-phishing-guard
#
# The port is published on 127.0.0.1 only. Do not expose it publicly.

FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    AIPHISH_HOST=0.0.0.0 \
    AIPHISH_PORT=5000

WORKDIR /app

COPY ml/requirements.txt ml/requirements.txt
RUN pip install --no-cache-dir -r ml/requirements.txt gunicorn

COPY shared/ shared/
COPY ml/*.py ml/
COPY ml/model/ ml/model/
COPY ml/evaluation_results.json ml/evaluation_results.json
COPY test-pages/ test-pages/

RUN useradd --create-home --uid 10001 guard
USER guard

EXPOSE 5000
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:5000/health', timeout=2).status == 200 else 1)"

WORKDIR /app/ml
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "2", "app:app"]
