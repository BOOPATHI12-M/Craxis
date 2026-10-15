# Craxis backend (Flask API + model).
#
# Build:  docker build -t craxis .
# Local:  docker run --rm -p 127.0.0.1:5000:5000 craxis
# Render: deploys this file as-is; the platform sets PORT (default 10000).

FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    AIPHISH_HOST=0.0.0.0 \
    PORT=5000

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
  CMD python -c "import os,urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:%s/health' % os.environ.get('PORT', '5000'), timeout=2).status == 200 else 1)"

WORKDIR /app/ml
CMD ["sh", "-c", "exec gunicorn --bind 0.0.0.0:${PORT:-5000} --workers 2 --timeout 30 app:app"]
