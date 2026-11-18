# AEGIS container image (optional; local Windows installation is the primary, tested mode).
# NOTE: written and reviewed but NOT built on the development machine (Docker is not installed there).
#
#   docker compose up --build   (from the repository root)

# ---------- frontend build ----------
# glibc base: the toolchain (TypeScript 7, Rolldown, Tailwind oxide) ships native binaries; musl builds are less certain.
FROM node:22-bookworm-slim AS frontend
WORKDIR /src/frontend
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci --no-fund --no-audit
COPY frontend/ ./
RUN npm run build

# ---------- runtime ----------
FROM python:3.12-slim AS runtime
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1 \
    AEGIS_ENV=production AEGIS_HOST=0.0.0.0 AEGIS_DATA_DIR=/data AEGIS_FRONTEND_DIST=/app/frontend/dist
# DejaVu fonts give the PDF reports full Unicode coverage (non-Latin directory names).
RUN apt-get update && apt-get install -y --no-install-recommends fonts-dejavu-core \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 10001 --home /app aegis
WORKDIR /app/backend
COPY backend/requirements.txt ./
RUN pip install -r requirements.txt
COPY backend/ ./
COPY sample_data/ /app/sample_data/
COPY --from=frontend /src/frontend/dist /app/frontend/dist
RUN mkdir -p /data && chown aegis /data
USER aegis
VOLUME ["/data"]
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/api/health').status == 200 else 1)"
CMD ["python", "-m", "uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1"]
