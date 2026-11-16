# --- Stage 1: build the React web app ------------------------------------------
FROM node:22-slim AS frontend
WORKDIR /frontend
COPY frontend/package.json frontend/package-lock.json* ./
RUN npm install --no-audit --no-fund
COPY frontend/ ./
RUN npm run build

# --- Stage 2: Python API, trained model and built web app ----------------------
FROM python:3.12-slim
RUN useradd --create-home --uid 10001 scamcheck
WORKDIR /app

COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install --no-cache-dir .

# Train the model at build time so the image is self-contained
COPY data ./data
ENV SCAMCHECK_DATA_DIR=/app/data
RUN python -m scamcheck.train --out /app/models/scamcheck.joblib --metrics /app/models/metrics.json

COPY --from=frontend /frontend/dist /app/frontend/dist
ENV SCAMCHECK_MODEL=/app/models/scamcheck.joblib \
    SCAMCHECK_FRONTEND=/app/frontend/dist \
    PYTHONUNBUFFERED=1

USER scamcheck
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=3s CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/api/health')"
CMD ["uvicorn", "scamcheck.api:app", "--host", "0.0.0.0", "--port", "8000", "--no-access-log"]
