# Ghiseul.ro for Home Assistant

Custom Home Assistant integration for [Ghiseul.ro](https://www.ghiseul.ro/) — the Romanian government's online payment portal. Monitor your pending debts, ANAF tax obligations, and local institution payments directly from your Home Assistant dashboard.

> **Disclaimer:** This integration is developed independently through reverse engineering for personal use. It is **not affiliated with, endorsed by, or supported by** Ghiseul.ro, SNEP, or the Romanian Government.

## Features

- **Total obligations** sensor — sum of all debts across ANAF and enrolled institutions
- **ANAF tax obligations** — individual obligation breakdown with amounts
- **ANAF status** — clear/obligations indicator
- **Per-institution debt sensors** — dynamically created for each enrolled institution
- **Institution count** — number of enrolled institutions
- Automatic retry with exponential backoff on transient errors
- Cached data — sensors stay available even when fetches temporarily fail
- Reauth flow — prompts for new credentials if authentication fails

## Prerequisites

This integration requires the **ghiseul-browser** microservice to be running and accessible from your Home Assistant instance. The microservice handles Cloudflare challenge solving and data scraping using a persistent Chromium browser.

### Deploy ghiseul-browser

The microservice is available as a Docker image:

```bash
docker run -d \
  --name ghiseul-browser \
  -p 8192:8192 \
  ghcr.io/emanuelbesliu/ghiseul-browser:v0.1.8
```

Or deploy to Kubernetes using the manifest in `infra/ghiseul-browser.yaml`.

Verify it's running:

```bash
curl http://<host>:8192/health
# {"status": "ok", ...}
```

## Installation

### HACS (Recommended)

1. Open HACS in Home Assistant
2. Click the three dots menu → **Custom repositories**
3. Add `https://github.com/emanuelbesliu/homeassistant-ghiseulro` as an **Integration**
4. Search for "Ghiseul.ro" and install
5. Restart Home Assistant

### Manual

1. Copy `custom_components/ghiseulro/` to your Home Assistant `config/custom_components/` directory
2. Restart Home Assistant

## Configuration

1. Go to **Settings** → **Devices & Services** → **Add Integration**
2. Search for "Ghiseul.ro"
3. Enter your Ghiseul.ro credentials and the browser service URL

| Field | Description | Default |
|---|---|---|
| Username | Your Ghiseul.ro username | — |
| Password | Your Ghiseul.ro password | — |
| Browser Service URL | URL of the ghiseul-browser microservice | `http://10.0.102.10:8192` |

## Sensors

| Sensor | Type | Unit | Description |
|---|---|---|---|
| Ghiseul.ro Total Obligații | monetary | RON | Sum of all obligations |
| Ghiseul.ro Instituții Înrolate | count | — | Number of enrolled institutions |
| Ghiseul.ro ANAF Obligații Fiscale | monetary | RON | Total ANAF tax obligations |
| Ghiseul.ro ANAF Status | text | — | `clear` or `obligations` |
| Ghiseul.ro *Institution Name* | monetary | RON | Per-institution debt (dynamic) |

All monetary sensors include detailed breakdowns in their attributes.

## Update Interval

Data is refreshed every **6 hours** (4 times per day). On failure, the integration retries with exponential backoff (5min, 10min, 20min, 40min cap).

## ☕ Support the Developer

If you find this project useful, consider buying me a coffee!

[!["Buy Me A Coffee"](https://www.buymeacoffee.com/assets/img/custom_images/orange_img.png)](https://buymeacoffee.com/emanuelbesliu)

## License

MIT License — Copyright (c) 2026 Emanuel Besliu
