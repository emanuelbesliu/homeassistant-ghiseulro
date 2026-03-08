FROM python:3.11-slim-bookworm

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
