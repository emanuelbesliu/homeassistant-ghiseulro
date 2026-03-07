"""Config flow for Ghiseul.ro integration.

Copyright (c) 2026 Emanuel Besliu
Licensed under the MIT License
"""
from __future__ import annotations

import logging
from typing import Any

import voluptuous as vol

from homeassistant import config_entries
from homeassistant.const import CONF_PASSWORD, CONF_USERNAME
from homeassistant.core import HomeAssistant
from homeassistant.data_entry_flow import FlowResult
from homeassistant.exceptions import HomeAssistantError

from .api import GhiseulRoAPI
from .const import CONF_FLARESOLVERR_URL, DEFAULT_FLARESOLVERR_URL, DOMAIN

_LOGGER = logging.getLogger(__name__)

STEP_USER_DATA_SCHEMA = vol.Schema(
    {
        vol.Required(CONF_USERNAME): str,
        vol.Required(CONF_PASSWORD): str,
        vol.Optional(
            CONF_FLARESOLVERR_URL, default=DEFAULT_FLARESOLVERR_URL
        ): str,
    }
)


async def validate_input(hass: HomeAssistant, data: dict[str, Any]) -> dict[str, Any]:
    """Validate the user input allows us to connect.

    Data has the keys from STEP_USER_DATA_SCHEMA with values provided by the user.
    """
    flaresolverr_url = data.get(CONF_FLARESOLVERR_URL, DEFAULT_FLARESOLVERR_URL)

    api = GhiseulRoAPI(
        data[CONF_USERNAME],
        data[CONF_PASSWORD],
        flaresolverr_url=flaresolverr_url,
    )

    try:
        # First verify FlareSolverr is reachable
        flaresolverr_ok = await api.async_test_flaresolverr()
        if not flaresolverr_ok:
            raise FlareSolverrUnavailable

        # Then verify credentials by authenticating
        result = await api.authenticate()
        if not result:
            raise InvalidAuth
    except FlareSolverrUnavailable:
        raise
    except InvalidAuth:
        raise
    except Exception as err:
        _LOGGER.error("Failed to authenticate: %s", err)
        raise CannotConnect from err
    finally:
        await api.async_close()

    return {"title": f"Ghiseul.ro - {data[CONF_USERNAME]}"}


class ConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    """Handle a config flow for Ghiseul.ro."""

    VERSION = 1

    async def async_step_user(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """Handle the initial step."""
        errors: dict[str, str] = {}

        if user_input is not None:
            try:
                info = await validate_input(self.hass, user_input)
            except FlareSolverrUnavailable:
                errors["base"] = "flaresolverr_unavailable"
            except CannotConnect:
                errors["base"] = "cannot_connect"
            except InvalidAuth:
                errors["base"] = "invalid_auth"
            except Exception:  # pylint: disable=broad-except
                _LOGGER.exception("Unexpected exception")
                errors["base"] = "unknown"
            else:
                return self.async_create_entry(title=info["title"], data=user_input)

        return self.async_show_form(
            step_id="user", data_schema=STEP_USER_DATA_SCHEMA, errors=errors
        )

    async def async_step_reauth(
        self, entry_data: dict[str, Any]
    ) -> FlowResult:
        """Handle reauth when credentials become invalid."""
        return await self.async_step_reauth_confirm()

    async def async_step_reauth_confirm(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """Handle reauth confirmation with new credentials."""
        errors: dict[str, str] = {}

        if user_input is not None:
            # Get the existing entry to preserve the username and FlareSolverr URL
            reauth_entry = self._get_reauth_entry()
            combined_data = {
                CONF_USERNAME: reauth_entry.data[CONF_USERNAME],
                CONF_PASSWORD: user_input[CONF_PASSWORD],
                CONF_FLARESOLVERR_URL: reauth_entry.data.get(
                    CONF_FLARESOLVERR_URL, DEFAULT_FLARESOLVERR_URL
                ),
            }

            try:
                await validate_input(self.hass, combined_data)
            except FlareSolverrUnavailable:
                errors["base"] = "flaresolverr_unavailable"
            except CannotConnect:
                errors["base"] = "cannot_connect"
            except InvalidAuth:
                errors["base"] = "invalid_auth"
            except Exception:  # pylint: disable=broad-except
                _LOGGER.exception("Unexpected exception during reauth")
                errors["base"] = "unknown"
            else:
                return self.async_update_reload_and_abort(
                    reauth_entry,
                    data=combined_data,
                )

        return self.async_show_form(
            step_id="reauth_confirm",
            data_schema=vol.Schema(
                {
                    vol.Required(CONF_PASSWORD): str,
                }
            ),
            errors=errors,
            description_placeholders={
                "username": self._get_reauth_entry().data.get(CONF_USERNAME, ""),
            },
        )


class CannotConnect(HomeAssistantError):
    """Error to indicate we cannot connect."""


class InvalidAuth(HomeAssistantError):
    """Error to indicate there is invalid auth."""


class FlareSolverrUnavailable(HomeAssistantError):
    """Error to indicate FlareSolverr is not reachable."""
