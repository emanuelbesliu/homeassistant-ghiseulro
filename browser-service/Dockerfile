FROM python:3.11-slim-bookworm

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
# tini is used as PID 1 so that Chrome's orphaned child processes are reaped
# instead of accumulating as zombies (which eventually exhausts fork()).
RUN apt-get update && apt-get install -y --no-install-recommends \
    tini \
    chromium \
    chromium-sandbox \
    xvfb \
    x11vnc \
    novnc \
    websockify \
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
# Keep the working browser API; display-based verification does not depend on
# an iframe being exposed by nodriver. Pin the image recognition/input runtime.
RUN pip install --no-cache-dir \
    aiohttp==3.13.3 \
    nodriver==0.48.1 \
    xvfbwrapper==0.2.34 \
    mss==10.2.0 \
    opencv-python-headless==5.0.0.93 \
    python-xlib==0.33

WORKDIR /app
COPY server.py native_verify.py ./

# Environment
ENV HEADLESS=true
ENV HOST=0.0.0.0
ENV PORT=8192
ENV LOG_LEVEL=INFO
ENV USER_DATA_DIR=/data/chrome
ENV CF_SOLVE_TIMEOUT=90
ENV CF_RETRY_COOLDOWN=300
ENV CF_NATIVE_CLICK=true

EXPOSE 8192 6080

# tini reaps zombie Chrome subprocesses (-g forwards signals to the process group)
ENTRYPOINT ["/usr/bin/tini", "-g", "--"]
CMD ["python", "server.py"]
