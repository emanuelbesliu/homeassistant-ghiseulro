FROM python:3.14-slim-bookworm

# OCI image labels (build-time args populated by CI)
ARG BUILD_DATE
ARG VCS_REF
ARG VERSION
LABEL org.opencontainers.image.title="ghiseul-browser" \
      org.opencontainers.image.description="Headless browser microservice for ghiseul.ro scraping via nodriver" \
      org.opencontainers.image.url="https://github.com/emanuelbesliu/homeassistant-ghiseulro" \
      org.opencontainers.image.source="https://github.com/emanuelbesliu/homeassistant-ghiseulro" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.created="${BUILD_DATE}" \
      org.opencontainers.image.revision="${VCS_REF}" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.vendor="emanuelbesliu"

# Install Chromium and dependencies (using default Debian repos)
RUN apt-get update && apt-get install -y --no-install-recommends \
    chromium \
    chromium-sandbox \
    xvfb \
    fonts-liberation \
    libasound2 \
    libatk-bridge2.0-0 \
    libatk1.0-0 \
    libcups2 \
    libdbus-1-3 \
    libdrm2 \
    libgbm1 \
    libgtk-3-0 \
    libnspr4 \
    libnss3 \
    libx11-xcb1 \
    libxcomposite1 \
    libxdamage1 \
    libxrandr2 \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
RUN pip install --no-cache-dir \
    aiohttp \
    nodriver \
    xvfbwrapper

WORKDIR /app
COPY server.py .

# Environment
ENV HEADLESS=true
ENV HOST=0.0.0.0
ENV PORT=8192
ENV LOG_LEVEL=INFO

EXPOSE 8192

CMD ["python", "server.py"]
