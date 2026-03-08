"""API client for Ghiseul.ro.

Copyright (c) 2026 Emanuel Besliu
Licensed under the MIT License

This integration was developed through reverse engineering of the
ghiseul.ro platform and is not affiliated with or endorsed by
Ghiseul.ro or the Romanian Government.

Architecture:
  The ghiseul.ro website is protected by Cloudflare Managed Challenge,
  which requires a real browser to bypass.  A companion microservice
  (ghiseul-browser) running nodriver keeps a persistent Chromium
  instance, solves the CF challenge, logs in, and scrapes all data
  in a single /scrape-all call.

  This API client simply:
    1. POSTs credentials to /scrape-all on the browser microservice
    2. Parses the HTML fragments in the response into structured data
    3. Returns the data dict expected by the coordinator / sensors
"""
from __future__ import annotations

import logging
import re
from typing import Any

import aiohttp

_LOGGER = logging.getLogger(__name__)

# Timeout for the /scrape-all call (CF solve ~25s + data scrape ~10s)
SCRAPE_TIMEOUT = aiohttp.ClientTimeout(total=120)


class GhiseulRoAPIError(Exception):
    """Base exception for Ghiseul.ro API errors."""


class AuthenticationError(GhiseulRoAPIError):
    """Authentication failed (wrong credentials or locked out)."""


class BrowserServiceError(GhiseulRoAPIError):
    """Browser microservice is unreachable or returned an error."""


class GhiseulRoAPI:
    """Client for the ghiseul-browser microservice."""

    def __init__(
        self,
        username: str,
        password: str,
        browser_service_url: str,
    ) -> None:
        """Initialize the API client."""
        self._username = username
        self._password = password
        self._browser_service_url = browser_service_url.rstrip("/")
        self._session: aiohttp.ClientSession | None = None

    def _get_session(self) -> aiohttp.ClientSession:
        """Get or create the aiohttp session."""
        if self._session is None or self._session.closed:
            self._session = aiohttp.ClientSession(timeout=SCRAPE_TIMEOUT)
        return self._session

    async def async_close(self) -> None:
        """Close the aiohttp session."""
        if self._session and not self._session.closed:
            await self._session.close()
            self._session = None

    # ------------------------------------------------------------------
    # Connectivity checks
    # ------------------------------------------------------------------

    async def async_test_connection(self) -> bool:
        """Test that the browser microservice is reachable."""
        try:
            session = self._get_session()
            async with session.get(
                f"{self._browser_service_url}/health",
                timeout=aiohttp.ClientTimeout(total=10),
            ) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    return data.get("status") == "ok"
                return False
        except Exception:
            return False

    async def authenticate(self) -> bool:
        """Test credentials by performing a full scrape.

        Returns True if login succeeds.
        Raises AuthenticationError on bad credentials.
        Raises BrowserServiceError on infrastructure issues.
        """
        data = await self.get_data()
        return data is not None

    # ------------------------------------------------------------------
    # Main data fetching
    # ------------------------------------------------------------------

    async def get_data(self) -> dict[str, Any]:
        """Fetch all data from ghiseul.ro via the browser microservice.

        Returns a structured dict ready for consumption by sensors:
        {
            "summary": {
                "grand_total": float,
                "anaf_total": float,
                "institutions_total": float,
                "institution_count": int,
            },
            "anaf": {
                "total": float,
                "has_obligations": bool,
                "cui": str,
                "message": str,
                "obligations": [...],
            },
            "institutions": {
                "inst_id": {
                    "name": str,
                    "total": float,
                    "has_debts": bool,
                    "debts": [...],
                },
            },
        }
        """
        session = self._get_session()

        try:
            async with session.post(
                f"{self._browser_service_url}/scrape-all",
                json={
                    "username": self._username,
                    "password": self._password,
                },
            ) as resp:
                body = await resp.json()

                if resp.status == 401:
                    login_resp = body.get("login_response", "")
                    msg = f"Authentication failed: {login_resp}"
                    _LOGGER.error(msg)
                    raise AuthenticationError(msg)

                if resp.status != 200 or body.get("status") != "ok":
                    error_msg = body.get("message", f"HTTP {resp.status}")
                    raise BrowserServiceError(
                        f"Browser service error: {error_msg}"
                    )

        except aiohttp.ClientError as err:
            raise BrowserServiceError(
                f"Cannot reach browser service at "
                f"{self._browser_service_url}: {err}"
            ) from err

        # Parse the raw HTML responses into structured data
        return self._parse_scrape_response(body)

    # ------------------------------------------------------------------
    # HTML parsing
    # ------------------------------------------------------------------

    def _parse_scrape_response(self, body: dict[str, Any]) -> dict[str, Any]:
        """Parse the /scrape-all response into sensor-friendly data."""
        # Parse institutions
        institutions = self._parse_institutions(
            body.get("institutions", [])
        )

        # Parse ANAF
        anaf = self._parse_anaf(
            body.get("anaf_page_html", ""),
            body.get("anaf_debts_html", ""),
        )

        # Compute summary
        institutions_total = sum(
            inst.get("total", 0.0) for inst in institutions.values()
        )
        anaf_total = anaf.get("total", 0.0)

        return {
            "summary": {
                "grand_total": round(institutions_total + anaf_total, 2),
                "anaf_total": anaf_total,
                "institutions_total": round(institutions_total, 2),
                "institution_count": len(institutions),
            },
            "anaf": anaf,
            "institutions": institutions,
        }

    def _parse_institutions(
        self, raw_institutions: list[dict[str, Any]]
    ) -> dict[str, dict[str, Any]]:
        """Parse institution data from the browser service response."""
        result: dict[str, dict[str, Any]] = {}

        for inst in raw_institutions:
            inst_id = str(inst.get("id", ""))
            if not inst_id:
                continue

            name = inst.get("name", "")
            total_str = inst.get("total", "0,00")
            details_html = inst.get("details_html", "")

            # Parse total (Romanian format: "1.234,56" -> 1234.56)
            total = self._parse_romanian_amount(total_str)

            # Parse individual debts from the details HTML
            debts = self._parse_institution_debts(details_html)

            # If name is empty, try to extract from institutions_html
            if not name:
                name = f"Instituție {inst_id}"

            result[inst_id] = {
                "name": name,
                "total": total,
                "has_debts": total > 0.0,
                "debts": debts,
            }

        return result

    def _parse_institution_debts(
        self, html: str
    ) -> list[dict[str, Any]]:
        """Parse individual debt rows from an institution details HTML."""
        debts: list[dict[str, Any]] = []
        if not html:
            return debts

        # Look for debt rows: each has a description and an amount input
        # Pattern: <td>Debt Name</td> ... <input ... value="amount" ...>
        row_pattern = re.compile(
            r'<tr[^>]*>\s*'
            r'<td[^>]*>.*?</td>\s*'  # checkbox or empty td
            r'<td[^>]*>(.*?)</td>\s*'  # debt name
            r'<td[^>]*>.*?value="([^"]*)"',  # amount input
            re.DOTALL | re.IGNORECASE,
        )

        for match in row_pattern.finditer(html):
            name_html = match.group(1)
            amount_str = match.group(2)

            # Strip HTML tags from name
            name = re.sub(r"<[^>]+>", "", name_html).strip()
            if not name or name.lower() == "total":
                continue

            amount = self._parse_romanian_amount(amount_str)
            if amount > 0:
                debts.append({"name": name, "amount": amount})

        return debts

    def _parse_anaf(
        self, page_html: str, debts_html: str
    ) -> dict[str, Any]:
        """Parse ANAF data from the page HTML and debts fragment."""
        result: dict[str, Any] = {
            "total": 0.0,
            "has_obligations": False,
            "cui": "",
            "message": "",
            "obligations": [],
        }

        # Extract CUI from the ANAF page (hidden input or profile header)
        if page_html:
            cui_match = re.search(
                r'name="cui_plata"\s+value="([^"]*)"', page_html
            )
            if cui_match:
                result["cui"] = cui_match.group(1)

        # Parse ANAF debts
        if not debts_html:
            result["message"] = "Nu s-au putut încărca obligațiile ANAF"
            return result

        # Check for "no obligations" message
        no_debts_patterns = [
            r"Nu exist[ăa] obliga[țt]ii de plat[ăa]",
            r"nu exist[ăa] sume de plat[ăa]",
        ]
        for pattern in no_debts_patterns:
            if re.search(pattern, debts_html, re.IGNORECASE):
                result["message"] = "Nu există obligații de plată"
                return result

        # Parse individual ANAF obligations
        # ANAF debts have rows with: type name, amount, details
        obligation_pattern = re.compile(
            r'<tr[^>]*>\s*'
            r'<td[^>]*>.*?</td>\s*'  # checkbox
            r'<td[^>]*>(.*?)</td>\s*'  # obligation name
            r'<td[^>]*>.*?value="([^"]*)"',  # amount
            re.DOTALL | re.IGNORECASE,
        )

        total = 0.0
        for match in obligation_pattern.finditer(debts_html):
            name_html = match.group(1)
            amount_str = match.group(2)

            name = re.sub(r"<[^>]+>", "", name_html).strip()
            if not name or name.lower() == "total":
                continue

            amount = self._parse_romanian_amount(amount_str)
            if amount > 0:
                result["obligations"].append({"name": name, "amount": amount})
                total += amount

        # Also check for TotalGeneral input
        total_match = re.search(
            r'id="TotalGeneral"\s+value="([^"]*)"', debts_html
        )
        if total_match:
            total = self._parse_romanian_amount(total_match.group(1))

        result["total"] = round(total, 2)
        result["has_obligations"] = total > 0.0

        if result["has_obligations"]:
            result["message"] = (
                f"Obligații fiscale ANAF: {total:.2f} RON"
            )
        else:
            result["message"] = "Nu există obligații de plată"

        # Check for somate (enforced) subtotal
        somate_match = re.search(
            r'id="subtotal"\s+value="([^"]*)"', debts_html
        )
        if somate_match:
            somate_total = self._parse_romanian_amount(somate_match.group(1))
            if somate_total > 0:
                result["subtotal_somate"] = somate_total

        return result

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _parse_romanian_amount(value: str) -> float:
        """Parse a Romanian-formatted amount string to float.

        Romanian format: 1.234,56 -> 1234.56
        Also handles plain floats: 0.00 -> 0.0
        """
        if not value or not value.strip():
            return 0.0
        value = value.strip()
        # Remove thousands separator (period) and replace decimal comma
        normalized = value.replace(".", "").replace(",", ".")
        try:
            return float(normalized)
        except ValueError:
            _LOGGER.debug("Could not parse amount: %s", value)
            return 0.0
