"""Data Update Coordinator for Ghiseul.ro.

Copyright (c) 2026 Emanuel Besliu
Licensed under the MIT License

This integration was developed through reverse engineering of the
ghiseul.ro platform and is not affiliated with or endorsed by
Ghiseul.ro or the Romanian Government.

Implements a resilient polling controller that:
- Updates data 4 times per day (every 6 hours)
- Caches last successful data so sensors never go unavailable on transient errors
- Retries with exponential backoff on failure (5m, 10m, 20m, 40m cap)
- Detects authentication failures and triggers a reauth flow instead of retrying
"""
from __future__ import annotations

import logging
from datetime import timedelta
from typing import Any

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import ConfigEntryAuthFailed
from homeassistant.helpers.update_coordinator import (
    DataUpdateCoordinator,
    UpdateFailed,
)

from .api import AuthenticationError, BrowserServiceError, GhiseulRoAPI
from .const import DOMAIN

_LOGGER = logging.getLogger(__name__)

# Normal polling interval: every 6 hours (4 times/day)
UPDATE_INTERVAL = timedelta(hours=6)

# Retry backoff schedule (minutes): 5, 10, 20, 40, 40, 40, ...
RETRY_BASE_MINUTES = 5
RETRY_MAX_MINUTES = 40


class GhiseulRoDataUpdateCoordinator(DataUpdateCoordinator[dict[str, Any]]):
    """Coordinator that fetches Ghiseul.ro data with resilient retry logic.

    On a successful fetch the data is cached and the next poll is in 6 hours.
    On a transient failure the cached data is preserved (sensors stay available)
    and the coordinator retries with exponential backoff.
    On an authentication failure a ConfigEntryAuthFailed is raised so Home
    Assistant shows the integration as "Requires reconfiguration".
    """

    def __init__(
        self,
        hass: HomeAssistant,
        entry: ConfigEntry,
        api: GhiseulRoAPI,
    ) -> None:
        """Initialize the coordinator."""
        self.entry = entry
        self.api = api
        self._retry_count: int = 0
        self._cached_data: dict[str, Any] | None = None

        super().__init__(
            hass,
            _LOGGER,
            name=DOMAIN,
            update_interval=UPDATE_INTERVAL,
        )

    # ------------------------------------------------------------------
    # Core update logic
    # ------------------------------------------------------------------

    async def _async_update_data(self) -> dict[str, Any]:
        """Fetch data from the Ghiseul.ro API.

        Returns cached data on transient errors so that sensors remain
        available.  Raises ConfigEntryAuthFailed on credential problems
        so that HA triggers the reauth flow.
        """
        try:
            data = await self.api.get_data()

            # Success - cache the data and reset retry state
            self._cached_data = data
            self._reset_retry()
            return data

        except Exception as err:
            if self._is_auth_error(err):
                _LOGGER.error(
                    "Ghiseul.ro authentication failed - credentials may "
                    "have changed. Integration will require reconfiguration: %s",
                    err,
                )
                raise ConfigEntryAuthFailed(
                    "Authentication failed. Please reconfigure the integration "
                    "with valid credentials."
                ) from err

            # Transient / network error - schedule a retry
            self._retry_count += 1
            next_retry = self._next_retry_interval()
            self.update_interval = next_retry

            _LOGGER.warning(
                "Ghiseul.ro data fetch failed (attempt %d). "
                "Retrying in %s. Error: %s",
                self._retry_count,
                next_retry,
                err,
            )

            # Return cached data so sensors stay available
            if self._cached_data is not None:
                return self._cached_data

            # No cache yet (first fetch ever failed) - propagate so HA
            # knows the integration is not ready
            raise UpdateFailed(
                f"Error communicating with Ghiseul.ro: {err}"
            ) from err

    # ------------------------------------------------------------------
    # Retry helpers
    # ------------------------------------------------------------------

    def _next_retry_interval(self) -> timedelta:
        """Calculate the next retry interval with exponential backoff."""
        minutes = min(
            RETRY_BASE_MINUTES * (2 ** (self._retry_count - 1)),
            RETRY_MAX_MINUTES,
        )
        return timedelta(minutes=minutes)

    def _reset_retry(self) -> None:
        """Reset retry state and restore the normal polling interval."""
        if self._retry_count > 0:
            _LOGGER.info(
                "Ghiseul.ro data fetch recovered after %d retries. "
                "Resuming normal 6-hour polling schedule.",
                self._retry_count,
            )
        self._retry_count = 0
        self.update_interval = UPDATE_INTERVAL

    # ------------------------------------------------------------------
    # Auth-error detection
    # ------------------------------------------------------------------

    @staticmethod
    def _is_auth_error(err: Exception) -> bool:
        """Determine whether an exception indicates an authentication problem.

        AuthenticationError from the API means bad credentials or locked out.
        BrowserServiceError means the microservice is down — that's transient.
        """
        # Explicit authentication failure from the API
        if isinstance(err, AuthenticationError):
            return True

        # Browser service issues are NOT auth errors — they are transient
        if isinstance(err, BrowserServiceError):
            return False

        # Fall back to inspecting the string representation
        err_str = str(err).lower()
        auth_keywords = (
            "unauthorized",
            "authentication failed",
            "invalid credentials",
            "login failed",
            "autentificare",
        )
        return any(kw in err_str for kw in auth_keywords)
