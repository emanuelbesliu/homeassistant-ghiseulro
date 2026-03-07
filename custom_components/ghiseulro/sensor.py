"""Sensor platform for Ghiseul.ro integration.

Copyright (c) 2026 Emanuel Besliu
Licensed under the MIT License
"""
from __future__ import annotations

import logging
from typing import Any

from homeassistant.components.sensor import (
    SensorDeviceClass,
    SensorEntity,
    SensorStateClass,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import (
    CoordinatorEntity,
    DataUpdateCoordinator,
)

from .const import DOMAIN

_LOGGER = logging.getLogger(__name__)


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up Ghiseul.ro sensors based on a config entry."""
    coordinator = hass.data[DOMAIN][entry.entry_id]["coordinator"]

    sensors: list[SensorEntity] = [
        # Global summary sensors
        GhiseulRoGrandTotalSensor(coordinator, entry),
        GhiseulRoInstitutionCountSensor(coordinator, entry),
        # ANAF sensors
        GhiseulRoAnafTotalSensor(coordinator, entry),
        GhiseulRoAnafStatusSensor(coordinator, entry),
    ]

    # Per-institution sensors (dynamically created)
    if coordinator.data and "institutions" in coordinator.data:
        for inst_id, inst_data in coordinator.data["institutions"].items():
            inst_name = inst_data.get("name", f"Instituție {inst_id}")
            sensors.append(
                GhiseulRoInstitutionDebtSensor(
                    coordinator, entry, inst_id, inst_name
                )
            )

    async_add_entities(sensors)


class GhiseulRoBaseSensor(CoordinatorEntity, SensorEntity):
    """Base class for Ghiseul.ro sensors."""

    def __init__(
        self,
        coordinator: DataUpdateCoordinator,
        entry: ConfigEntry,
        sensor_type: str,
        name: str,
    ) -> None:
        """Initialize the sensor."""
        super().__init__(coordinator)
        self._attr_unique_id = f"{entry.entry_id}_{sensor_type}"
        self._attr_name = f"Ghiseul.ro {name}"
        self._attr_device_info = {
            "identifiers": {(DOMAIN, entry.entry_id)},
            "name": "Ghiseul.ro",
            "manufacturer": "Ghiseul.ro - SNEP",
            "model": "Obligații de Plată",
        }


class GhiseulRoGrandTotalSensor(GhiseulRoBaseSensor):
    """Sensor for total obligations across ANAF and all institutions."""

    def __init__(
        self,
        coordinator: DataUpdateCoordinator,
        entry: ConfigEntry,
    ) -> None:
        """Initialize the sensor."""
        super().__init__(coordinator, entry, "grand_total", "Total Obligații")
        self._attr_device_class = SensorDeviceClass.MONETARY
        self._attr_state_class = SensorStateClass.TOTAL
        self._attr_native_unit_of_measurement = "RON"
        self._attr_icon = "mdi:cash-multiple"

    @property
    def native_value(self) -> float | None:
        """Return the total of all obligations."""
        if self.coordinator.data and "summary" in self.coordinator.data:
            return self.coordinator.data["summary"].get("grand_total", 0.0)
        return None

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        """Return breakdown by source."""
        attrs: dict[str, Any] = {}
        if self.coordinator.data and "summary" in self.coordinator.data:
            summary = self.coordinator.data["summary"]
            attrs["anaf_total"] = summary.get("anaf_total", 0.0)
            attrs["institutions_total"] = summary.get("institutions_total", 0.0)
            attrs["institution_count"] = summary.get("institution_count", 0)
        return attrs


class GhiseulRoInstitutionCountSensor(GhiseulRoBaseSensor):
    """Sensor for number of enrolled institutions with debts."""

    def __init__(
        self,
        coordinator: DataUpdateCoordinator,
        entry: ConfigEntry,
    ) -> None:
        """Initialize the sensor."""
        super().__init__(coordinator, entry, "institution_count", "Instituții Înrolate")
        self._attr_icon = "mdi:domain"

    @property
    def native_value(self) -> int | None:
        """Return the number of institutions."""
        if self.coordinator.data and "summary" in self.coordinator.data:
            return self.coordinator.data["summary"].get("institution_count", 0)
        return None

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        """Return institution names."""
        attrs: dict[str, Any] = {}
        if self.coordinator.data and "institutions" in self.coordinator.data:
            institutions = self.coordinator.data["institutions"]
            attrs["institutions"] = {
                inst_id: inst_data.get("name", "Unknown")
                for inst_id, inst_data in institutions.items()
            }
            # Count institutions with active debts
            with_debts = sum(
                1
                for inst_data in institutions.values()
                if inst_data.get("has_debts", False)
            )
            attrs["with_active_debts"] = with_debts
        return attrs


class GhiseulRoAnafTotalSensor(GhiseulRoBaseSensor):
    """Sensor for ANAF total tax obligations."""

    def __init__(
        self,
        coordinator: DataUpdateCoordinator,
        entry: ConfigEntry,
    ) -> None:
        """Initialize the sensor."""
        super().__init__(coordinator, entry, "anaf_total", "ANAF Obligații Fiscale")
        self._attr_device_class = SensorDeviceClass.MONETARY
        self._attr_state_class = SensorStateClass.TOTAL
        self._attr_native_unit_of_measurement = "RON"
        self._attr_icon = "mdi:bank"

    @property
    def native_value(self) -> float | None:
        """Return the ANAF total obligations."""
        if self.coordinator.data and "anaf" in self.coordinator.data:
            return self.coordinator.data["anaf"].get("total", 0.0)
        return None

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        """Return ANAF obligation details."""
        attrs: dict[str, Any] = {}
        if self.coordinator.data and "anaf" in self.coordinator.data:
            anaf = self.coordinator.data["anaf"]
            attrs["has_obligations"] = anaf.get("has_obligations", False)
            attrs["cui"] = anaf.get("cui", "")
            attrs["message"] = anaf.get("message", "")

            if anaf.get("subtotal_somate"):
                attrs["subtotal_somate"] = anaf["subtotal_somate"]

            # Individual obligation breakdown
            obligations = anaf.get("obligations", [])
            if obligations:
                breakdown: dict[str, float] = {}
                for obligation in obligations:
                    name = obligation.get("name", "Unknown")
                    amount = obligation.get("amount", 0.0)
                    breakdown[name] = amount
                attrs["breakdown"] = breakdown
                attrs["obligation_count"] = len(obligations)

                # Also add as individual attributes for easy templating
                for obligation in obligations:
                    name = obligation.get("name", "Unknown")
                    safe_name = self._normalize_attr_name(name)
                    attrs[f"obligation_{safe_name}"] = obligation.get("amount", 0.0)

        return attrs

    @staticmethod
    def _normalize_attr_name(name: str) -> str:
        """Normalize a Romanian name to a safe attribute key."""
        safe = name.lower()
        # Replace Romanian diacritics
        replacements = {
            "ă": "a", "â": "a", "î": "i",
            "ș": "s", "ț": "t", "ş": "s", "ţ": "t",
        }
        for old, new in replacements.items():
            safe = safe.replace(old, new)
        # Replace non-alphanumeric with underscore
        safe = "".join(c if c.isalnum() or c == "_" else "_" for c in safe)
        # Collapse multiple underscores
        safe = "_".join(filter(None, safe.split("_")))
        return safe


class GhiseulRoAnafStatusSensor(GhiseulRoBaseSensor):
    """Sensor for ANAF obligation status (has obligations or not)."""

    def __init__(
        self,
        coordinator: DataUpdateCoordinator,
        entry: ConfigEntry,
    ) -> None:
        """Initialize the sensor."""
        super().__init__(coordinator, entry, "anaf_status", "ANAF Status")
        self._attr_icon = "mdi:check-decagram"

    @property
    def native_value(self) -> str | None:
        """Return 'clear' if no obligations, 'obligations' if debts exist."""
        if self.coordinator.data and "anaf" in self.coordinator.data:
            anaf = self.coordinator.data["anaf"]
            if anaf.get("has_obligations", False):
                return "obligations"
            return "clear"
        return None

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        """Return status details."""
        attrs: dict[str, Any] = {}
        if self.coordinator.data and "anaf" in self.coordinator.data:
            anaf = self.coordinator.data["anaf"]
            attrs["total"] = anaf.get("total", 0.0)
            attrs["message"] = anaf.get("message", "")
            attrs["cui"] = anaf.get("cui", "")
            attrs["obligation_count"] = len(anaf.get("obligations", []))
        return attrs


class GhiseulRoInstitutionDebtSensor(GhiseulRoBaseSensor):
    """Sensor for debts at a specific institution."""

    def __init__(
        self,
        coordinator: DataUpdateCoordinator,
        entry: ConfigEntry,
        institution_id: str,
        institution_name: str,
    ) -> None:
        """Initialize the sensor."""
        # Create a short safe name for the sensor
        short_name = institution_name[:40] if len(institution_name) > 40 else institution_name
        super().__init__(
            coordinator,
            entry,
            f"institution_{institution_id}",
            short_name,
        )
        self._institution_id = institution_id
        self._attr_device_class = SensorDeviceClass.MONETARY
        self._attr_state_class = SensorStateClass.TOTAL
        self._attr_native_unit_of_measurement = "RON"
        self._attr_icon = "mdi:office-building"

    @property
    def native_value(self) -> float | None:
        """Return the total debt at this institution."""
        if self.coordinator.data and "institutions" in self.coordinator.data:
            inst_data = self.coordinator.data["institutions"].get(
                self._institution_id
            )
            if inst_data:
                return inst_data.get("total", 0.0)
        return None

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        """Return institution debt details."""
        attrs: dict[str, Any] = {}
        if self.coordinator.data and "institutions" in self.coordinator.data:
            inst_data = self.coordinator.data["institutions"].get(
                self._institution_id
            )
            if inst_data:
                attrs["institution_name"] = inst_data.get("name", "Unknown")
                attrs["institution_id"] = self._institution_id
                attrs["has_debts"] = inst_data.get("has_debts", False)

                if inst_data.get("error"):
                    attrs["error"] = inst_data["error"]

                # Debt breakdown
                debts = inst_data.get("debts", [])
                if debts:
                    breakdown: dict[str, float] = {}
                    for debt in debts:
                        name = debt.get("name", "Unknown")
                        amount = debt.get("amount", 0.0)
                        breakdown[name] = amount
                    attrs["breakdown"] = breakdown
                    attrs["debt_count"] = len(debts)

        return attrs
