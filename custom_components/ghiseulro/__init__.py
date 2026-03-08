"""The Ghiseul.ro integration.

Copyright (c) 2026 Emanuel Besliu
Licensed under the MIT License

This integration was developed through reverse engineering of the
ghiseul.ro platform and is not affiliated with or endorsed by
Ghiseul.ro or the Romanian Government.
"""
from __future__ import annotations

import logging

from homeassistant.config_entries import ConfigEntry
from homeassistant.const import CONF_PASSWORD, CONF_USERNAME, Platform
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import ConfigEntryNotReady

from .api import BrowserServiceError, GhiseulRoAPI
from .const import CONF_BROWSER_SERVICE_URL, DEFAULT_BROWSER_SERVICE_URL, DOMAIN
from .coordinator import GhiseulRoDataUpdateCoordinator

_LOGGER = logging.getLogger(__name__)

PLATFORMS: list[Platform] = [Platform.SENSOR]


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Set up Ghiseul.ro from a config entry."""
    api = GhiseulRoAPI(
        entry.data[CONF_USERNAME],
        entry.data[CONF_PASSWORD],
        browser_service_url=entry.data.get(
            CONF_BROWSER_SERVICE_URL, DEFAULT_BROWSER_SERVICE_URL
        ),
    )

    # Verify the browser service is reachable before proceeding
    try:
        reachable = await api.async_test_connection()
        if not reachable:
            await api.async_close()
            raise ConfigEntryNotReady(
                "Browser service is not reachable. "
                "Check that ghiseul-browser is running."
            )
    except BrowserServiceError as err:
        await api.async_close()
        raise ConfigEntryNotReady from err
    except Exception as err:
        await api.async_close()
        _LOGGER.error("Failed to connect to browser service: %s", err)
        raise ConfigEntryNotReady from err

    coordinator = GhiseulRoDataUpdateCoordinator(hass, entry, api)

    # First refresh fetches data (login + scrape) via the browser service.
    # Auth failures will raise ConfigEntryAuthFailed inside the coordinator.
    await coordinator.async_config_entry_first_refresh()

    hass.data.setdefault(DOMAIN, {})
    hass.data[DOMAIN][entry.entry_id] = {
        "coordinator": coordinator,
        "api": api,
    }

    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)

    return True


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Unload a config entry."""
    if unload_ok := await hass.config_entries.async_unload_platforms(entry, PLATFORMS):
        data = hass.data[DOMAIN].pop(entry.entry_id)
        api: GhiseulRoAPI = data["api"]
        await api.async_close()

    return unload_ok
