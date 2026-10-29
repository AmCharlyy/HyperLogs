FROM node:22-alpine AS frontend
WORKDIR /build
COPY package.json package-lock.json ./
RUN npm ci
COPY index.html vite.config.js ./
COPY src ./src
RUN npm run build

FROM python:3.12-slim AS application
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    HYPERLOGS_DATA=/var/lib/hyperlogs
WORKDIR /app
RUN apt-get update \
 && apt-get install --no-install-recommends --yes iputils-ping \
 && rm -rf /var/lib/apt/lists/* \
 && groupadd --system --gid 10001 hyperlogs \
 && useradd --system --uid 10001 --gid 10001 --home-dir /var/lib/hyperlogs --no-create-home hyperlogs \
 && mkdir -p /var/lib/hyperlogs \
 && chown 10001:10001 /var/lib/hyperlogs
COPY requirements.lock ./requirements.lock
RUN python -m pip install --no-cache-dir --requirement requirements.lock
COPY --chown=0:0 backend ./backend
COPY --from=frontend --chown=0:0 /build/dist ./dist
USER 10001:10001
EXPOSE 8000
CMD ["python", "-m", "uvicorn", "backend.app:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1", "--proxy-headers", "--forwarded-allow-ips", "*", "--limit-concurrency", "64", "--timeout-keep-alive", "5", "--no-server-header"]
