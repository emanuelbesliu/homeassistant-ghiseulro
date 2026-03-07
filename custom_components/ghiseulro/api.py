"""API client for Ghiseul.ro.

Copyright (c) 2026 Emanuel Besliu
Licensed under the MIT License

This integration was developed through reverse engineering of the
ghiseul.ro platform and is not affiliated with or endorsed by
Ghiseul.ro or the Romanian Government.

The API flow:
1. POST /login/process with username+password (AJAX, x-www-form-urlencoded)
   - Session cookie is managed automatically by cloudscraper
2. GET /debite/institutii (AJAX) -> HTML fragment listing enrolled institutions
3. GET /debite/get-institution-details/id_inst/{id} (AJAX) -> institution debt details
4. GET /debite/anaf -> full page with ANAF section (contains CUI, tipPers, id_inst)
5. GET /debite/incarca-debite-anaf (AJAX) -> HTML fragment with ANAF obligations

Uses cloudscraper to bypass Cloudflare/WAF bot-protection challenges.
cloudscraper is synchronous (requests-based), so all HTTP calls are
dispatched to an executor via asyncio.to_thread() to avoid blocking
the Home Assistant event loop.
"""
from __future__ import annotations

import asyncio
import logging
import re
from typing import Any

import cloudscraper

from .const import (
    BASE_URL,
    LOGIN_URL,
    DEBITE_URL,
    DEBITE_INSTITUTII_URL,
    DEBITE_INSTITUTION_DETAILS_URL,
    DEBITE_ANAF_URL,
    DEBITE_INCARCA_ANAF_URL,
    IS_LOGGED_IN_URL,
    ANAF_INSTITUTION_ID,
)

_LOGGER = logging.getLogger(__name__)


class GhiseulRoAPI:
    """API client for the Ghiseul.ro platform.

    Uses cloudscraper (a requests.Session subclass) to handle WAF
    bot-protection challenges automatically.  All HTTP calls run in
    a thread-pool executor so the HA event loop is never blocked.
    """

    def __init__(self, username: str, password: str) -> None:
        """Initialize the API client."""
        self._username = username
        self._password = password
        self._scraper: cloudscraper.CloudScraper | None = None
        self._authenticated = False

    def _get_scraper(self) -> cloudscraper.CloudScraper:
        """Get or create the cloudscraper session."""
        if self._scraper is None:
            _LOGGER.debug("Creating new cloudscraper session")
            self._scraper = cloudscraper.create_scraper(
                browser={
                    "browser": "chrome",
                    "platform": "windows",
                    "desktop": True,
                },
            )
            _LOGGER.debug(
                "Cloudscraper session created. User-Agent: %s",
                self._scraper.headers.get("User-Agent", "N/A"),
            )
        return self._scraper

    async def async_close(self) -> None:
        """Close the underlying requests session."""
        if self._scraper is not None:
            self._scraper.close()
            self._scraper = None

    # ------------------------------------------------------------------
    # Authentication
    # ------------------------------------------------------------------

    async def authenticate(self) -> bool:
        """Authenticate with the Ghiseul.ro platform (async wrapper)."""
        return await asyncio.to_thread(self._authenticate_sync)

    def _authenticate_sync(self) -> bool:
        """Authenticate with the Ghiseul.ro platform.

        The authentication flow:
        1. GET the base page first to obtain WAF clearance cookies
        2. POST /login/process with username and password
        3. Verify session by checking /index/este-logat
        """
        try:
            scraper = self._get_scraper()

            # Step 0: Hit the base URL first to solve any WAF challenge
            # and obtain clearance cookies before attempting login
            _LOGGER.debug(
                "Step 0: Fetching base URL to solve WAF challenge: %s",
                BASE_URL,
            )
            response = scraper.get(f"{BASE_URL}/")
            _LOGGER.debug(
                "Step 0 result: status=%s, url=%s, body_length=%d",
                response.status_code,
                response.url,
                len(response.text),
            )
            _LOGGER.debug(
                "Step 0 response headers: %s",
                dict(response.headers),
            )
            _LOGGER.debug(
                "Step 0 cookies after base page: %s",
                {k: v for k, v in scraper.cookies.get_dict().items()},
            )
            # Check if WAF challenge page was returned instead of real content
            if "security verification" in response.text.lower() or response.status_code == 403:
                _LOGGER.warning(
                    "Step 0: WAF challenge page detected (status=%s). "
                    "Body snippet: %.500s",
                    response.status_code,
                    response.text[:500],
                )
            else:
                _LOGGER.debug(
                    "Step 0: Base page loaded OK. Body snippet: %.300s",
                    response.text[:300],
                )

            # Step 1: POST login
            login_data = {
                "username": self._username,
                "password": self._password,
            }

            headers = {
                "X-Requested-With": "XMLHttpRequest",
                "Referer": f"{BASE_URL}/",
                "Origin": "https://www.ghiseul.ro",
                "Accept": "text/html, */*; q=0.01",
                "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
            }

            _LOGGER.debug("Step 1: Posting login to %s", LOGIN_URL)
            response = scraper.post(
                LOGIN_URL,
                data=login_data,
                headers=headers,
            )
            _LOGGER.debug(
                "Step 1 result: status=%s, url=%s, body_length=%d",
                response.status_code,
                response.url,
                len(response.text),
            )
            _LOGGER.debug(
                "Step 1 response headers: %s",
                dict(response.headers),
            )
            _LOGGER.debug(
                "Step 1 cookies: %s",
                {k: v for k, v in scraper.cookies.get_dict().items()},
            )

            if response.status_code != 200:
                _LOGGER.error(
                    "Login request failed with status: %s. "
                    "Response headers: %s. Body snippet: %.500s",
                    response.status_code,
                    dict(response.headers),
                    response.text[:500],
                )
                return False

            _LOGGER.debug(
                "Step 1 login response body: %.300s", response.text[:300]
            )

            # Step 2: Verify we are logged in
            _LOGGER.debug("Step 2: Verifying login via %s", IS_LOGGED_IN_URL)
            response = scraper.post(
                IS_LOGGED_IN_URL,
                headers={"X-Requested-With": "XMLHttpRequest"},
            )
            _LOGGER.debug(
                "Step 2 result: status=%s, body='%s'",
                response.status_code,
                response.text[:100].strip(),
            )

            if response.status_code == 200:
                body = response.text.strip()
                if body == "1":
                    self._authenticated = True
                    _LOGGER.info("Successfully authenticated with Ghiseul.ro")
                    return True
                else:
                    _LOGGER.error(
                        "Login verification failed: este-logat returned '%s'",
                        body[:50],
                    )
                    return False
            else:
                _LOGGER.error(
                    "Login verification failed with status: %s. "
                    "Body: %.300s",
                    response.status_code,
                    response.text[:300],
                )
                return False

        except cloudscraper.exceptions.CloudflareChallengeError as err:
            _LOGGER.error(
                "Cloudscraper failed to solve WAF challenge: %s", err
            )
            raise
        except Exception as err:
            _LOGGER.error(
                "Authentication error (%s): %s", type(err).__name__, err
            )
            raise

    # ------------------------------------------------------------------
    # Data fetching
    # ------------------------------------------------------------------

    async def get_data(self) -> dict[str, Any]:
        """Fetch all data: ANAF obligations and institution debts.

        Returns data structure:
        {
            "anaf": {
                "has_obligations": bool,
                "total": float,
                "obligations": [
                    {
                        "name": str,
                        "amount": float,
                    }
                ],
                "cui": str,
                "message": str,
            },
            "institutions": {
                "<id>": {
                    "name": str,
                    "has_debts": bool,
                    "total": float,
                    "debts": [
                        {
                            "name": str,
                            "amount": float,
                        }
                    ],
                }
            },
            "summary": {
                "anaf_total": float,
                "institutions_total": float,
                "grand_total": float,
                "institution_count": int,
            }
        }
        """
        if not self._authenticated:
            await self.authenticate()

        return await asyncio.to_thread(self._get_data_sync)

    def _get_data_sync(self) -> dict[str, Any]:
        """Fetch all data synchronously (runs in executor thread)."""
        anaf_data = self._fetch_anaf_obligations_sync()
        institutions_data = self._fetch_institution_debts_sync()

        # Build summary
        anaf_total = anaf_data.get("total", 0.0)
        institutions_total = sum(
            inst.get("total", 0.0) for inst in institutions_data.values()
        )

        return {
            "anaf": anaf_data,
            "institutions": institutions_data,
            "summary": {
                "anaf_total": anaf_total,
                "institutions_total": institutions_total,
                "grand_total": anaf_total + institutions_total,
                "institution_count": len(institutions_data),
            },
        }

    # ------------------------------------------------------------------
    # ANAF obligations
    # ------------------------------------------------------------------

    def _fetch_anaf_obligations_sync(self) -> dict[str, Any]:
        """Fetch ANAF tax obligations.

        First loads /debite/anaf to get the ANAF page context (CUI, tipPers),
        then calls /debite/incarca-debite-anaf which returns an HTML fragment
        with actual obligation data.
        """
        result: dict[str, Any] = {
            "has_obligations": False,
            "total": 0.0,
            "obligations": [],
            "cui": "",
            "message": "",
        }

        try:
            scraper = self._get_scraper()

            # Step 1: Load ANAF page to establish context and extract CUI
            response = scraper.get(
                DEBITE_ANAF_URL,
                headers={"Referer": DEBITE_URL},
            )
            if response.status_code != 200:
                _LOGGER.error(
                    "Failed to load ANAF page: %s", response.status_code
                )
                raise Exception(
                    f"Failed to load ANAF page: {response.status_code}"
                )

            html = response.text

            # Extract CUI from hidden input
            cui_match = re.search(
                r'name="cui_plata"\s+value="(\d+)"', html
            )
            if cui_match:
                result["cui"] = cui_match.group(1)
                _LOGGER.debug("Found CUI in ANAF page")

            # Extract tipPers
            tip_match = re.search(
                r'name="tipPers"\s+value="(\d+)"', html
            )
            if tip_match:
                result["tip_pers"] = tip_match.group(1)

            # Step 2: Load actual ANAF obligations via AJAX
            ajax_headers = {
                "X-Requested-With": "XMLHttpRequest",
                "Referer": DEBITE_ANAF_URL,
            }
            response = scraper.get(
                DEBITE_INCARCA_ANAF_URL,
                headers=ajax_headers,
            )
            if response.status_code != 200:
                _LOGGER.error(
                    "Failed to load ANAF obligations: %s",
                    response.status_code,
                )
                raise Exception(
                    f"Failed to load ANAF obligations: {response.status_code}"
                )

            html = response.text
            _LOGGER.debug("ANAF obligations HTML length: %d", len(html))

            result.update(self._parse_anaf_obligations(html))

        except Exception as err:
            _LOGGER.error("Error fetching ANAF obligations: %s", err)
            raise

        return result

    def _parse_anaf_obligations(self, html: str) -> dict[str, Any]:
        """Parse the ANAF obligations HTML fragment.

        The response can be:
        1. "Nu exista obligatii de plata" - no debts
        2. HTML table with obligation rows containing:
           - Income type (tip venit)
           - Amount (suma)
           - Details expandable sections

        Structure when debts exist:
        <table class="table...">
          <tr> with tip venit name and amount
          <tr class="detalii_venit_..."> with breakdown details
        </table>
        Plus a TotalGeneral input with the grand total.
        """
        parsed: dict[str, Any] = {
            "has_obligations": False,
            "total": 0.0,
            "obligations": [],
            "message": "",
        }

        # Check for "no obligations" message
        if (
            "Nu există obligații de plată" in html
            or "nu exista obligatii" in html.lower()
        ):
            parsed["message"] = "Nu există obligații de plată"
            return parsed

        # Check for error/info messages
        alert_match = re.search(
            r'<div\s+class=["\']alert\s+alert-(?:warning|danger|info)["\']>'
            r"(.*?)</div>",
            html,
            re.DOTALL,
        )
        if alert_match:
            msg = re.sub(r"<[^>]+>", "", alert_match.group(1)).strip()
            parsed["message"] = msg

        # Try to parse obligation rows
        obligations = []

        # Look for income type rows with amounts
        amount_matches = re.findall(
            r"id=['\"]suma_venit_(\d+)['\"][^>]*>([\d.,]+)</",
            html,
        )

        if amount_matches:
            parsed["has_obligations"] = True

            for venit_id, amount_str in amount_matches:
                amount = self._parse_amount(amount_str)

                # Try to find the label for this income type
                name = f"Obligație fiscală {venit_id}"

                # Look for label near this venit_id
                label_pattern = (
                    rf"showDetaliiVenit\([^,]*,\s*\d+\s*,\s*{venit_id}\s*\)"
                    rf"[^>]*>([^<]+)<"
                )
                label_match = re.search(label_pattern, html)
                if label_match:
                    name = label_match.group(1).strip()
                else:
                    # Try broader pattern
                    broader_pattern = (
                        rf"<tr[^>]*>.*?(?:showDetaliiVenit|venit)"
                        rf"[^>]*{venit_id}[^>]*>"
                        rf".*?<td[^>]*>([^<]+)</td>"
                    )
                    broader_match = re.search(
                        broader_pattern, html, re.DOTALL
                    )
                    if broader_match:
                        name = broader_match.group(1).strip()

                obligations.append(
                    {
                        "id": venit_id,
                        "name": name,
                        "amount": amount,
                    }
                )

                parsed["total"] += amount

        # Also check for TotalGeneral input as a fallback/verification
        total_match = re.search(
            r"id=['\"]TotalGeneral['\"][^>]*value=['\"]([^'\"]+)['\"]",
            html,
        )
        if total_match:
            total_val = self._parse_amount(total_match.group(1))
            if total_val > 0:
                parsed["has_obligations"] = True
                if not obligations:
                    # We have a total but couldn't parse individual items
                    parsed["total"] = total_val
                    obligations.append(
                        {
                            "id": "unknown",
                            "name": "Obligații fiscale ANAF",
                            "amount": total_val,
                        }
                    )

        # Check for subtotal (somated amounts)
        subtotal_match = re.search(
            r"id=['\"]subtotal_init['\"][^>]*>([\d.,]+)</",
            html,
        )
        if subtotal_match:
            parsed["subtotal_somate"] = self._parse_amount(
                subtotal_match.group(1)
            )

        # Look for input fields with suma_plata_ which indicate payable items
        plata_matches = re.findall(
            r'name=["\']suma_plata_(\d+)["\'][^>]*value=["\']([^"\']*)["\']',
            html,
        )
        if plata_matches and not amount_matches:
            parsed["has_obligations"] = True
            for venit_id, amount_str in plata_matches:
                if amount_str:
                    amount = self._parse_amount(amount_str)
                    if amount > 0:
                        obligations.append(
                            {
                                "id": venit_id,
                                "name": f"Obligație fiscală {venit_id}",
                                "amount": amount,
                            }
                        )
                        parsed["total"] += amount

        parsed["obligations"] = obligations
        return parsed

    # ------------------------------------------------------------------
    # Institution debts
    # ------------------------------------------------------------------

    def _fetch_institution_debts_sync(self) -> dict[str, dict[str, Any]]:
        """Fetch debts from enrolled institutions (non-ANAF).

        Calls /debite/institutii to get the list of institutions,
        then /debite/get-institution-details/id_inst/{id} for each
        to get debt details.
        """
        institutions: dict[str, dict[str, Any]] = {}

        try:
            scraper = self._get_scraper()

            # Step 1: Get institution list
            ajax_headers = {
                "X-Requested-With": "XMLHttpRequest",
                "Referer": DEBITE_URL,
            }

            response = scraper.get(
                DEBITE_INSTITUTII_URL,
                headers=ajax_headers,
            )
            if response.status_code != 200:
                _LOGGER.error(
                    "Failed to load institutions: %s", response.status_code
                )
                return institutions

            html = response.text
            _LOGGER.debug("Institutions HTML length: %d", len(html))

            # Parse institution IDs and names from HTML
            inst_list = self._parse_institution_list(html)

            # Step 2: Get details for each institution
            for inst_id, inst_name in inst_list:
                # Skip ANAF - it's handled separately
                if inst_id == ANAF_INSTITUTION_ID:
                    continue

                try:
                    details = self._fetch_single_institution_sync(inst_id)
                    institutions[inst_id] = {
                        "name": inst_name,
                        **details,
                    }
                except Exception as err:
                    _LOGGER.warning(
                        "Failed to fetch details for institution %s (%s): %s",
                        inst_id,
                        inst_name,
                        err,
                    )
                    institutions[inst_id] = {
                        "name": inst_name,
                        "has_debts": False,
                        "total": 0.0,
                        "debts": [],
                        "error": str(err),
                    }

        except Exception as err:
            _LOGGER.error("Error fetching institution debts: %s", err)
            raise

        return institutions

    def _parse_institution_list(self, html: str) -> list[tuple[str, str]]:
        """Parse the institution list HTML fragment.

        Returns list of (institution_id, institution_name) tuples.

        The HTML fragment from /debite/institutii contains panels/divs
        with institution IDs and names. The structure varies but typically
        includes elements referencing institution IDs.
        """
        institutions = []

        # Pattern 1: Panel with id attribute and heading text
        panel_pattern = re.findall(
            r'<div[^>]*class=["\'][^"\']*panel[^"\']*["\'][^>]*'
            r'id=["\'](\d+)["\']'
            r'[^>]*>.*?<div[^>]*class=["\'][^"\']*panel-heading'
            r'[^"\']*["\'][^>]*>(.*?)(?:</div>|<a)',
            html,
            re.DOTALL,
        )
        for inst_id, name_html in panel_pattern:
            name = re.sub(r"<[^>]+>", "", name_html).strip()
            if name and inst_id:
                institutions.append((inst_id, name))

        if institutions:
            return institutions

        # Pattern 2: Links with institution IDs
        link_pattern = re.findall(
            r"id_inst[/=](\d+).*?>(.*?)<",
            html,
            re.DOTALL,
        )
        for inst_id, name in link_pattern:
            name = name.strip()
            if name and inst_id:
                institutions.append((inst_id, name))

        if institutions:
            return institutions

        # Pattern 3: Look for data attributes or onclick handlers
        onclick_pattern = re.findall(
            r"(?:showDetalii|getInstitution|id_inst)[^(]*\((\d+)\)"
            r".*?>(.*?)<",
            html,
            re.DOTALL,
        )
        for inst_id, name in onclick_pattern:
            name = name.strip()
            if name and inst_id:
                institutions.append((inst_id, name))

        # Deduplicate
        seen: set[str] = set()
        unique = []
        for inst_id, name in institutions:
            if inst_id not in seen:
                seen.add(inst_id)
                unique.append((inst_id, name))

        return unique

    def _fetch_single_institution_sync(
        self, inst_id: str
    ) -> dict[str, Any]:
        """Fetch debt details for a single institution.

        Returns:
        {
            "has_debts": bool,
            "total": float,
            "debts": [{"name": str, "amount": float}],
        }
        """
        scraper = self._get_scraper()
        url = DEBITE_INSTITUTION_DETAILS_URL.format(id_inst=inst_id)
        ajax_headers = {
            "X-Requested-With": "XMLHttpRequest",
            "Referer": DEBITE_URL,
        }

        response = scraper.get(url, headers=ajax_headers)
        if response.status_code != 200:
            raise Exception(
                f"Failed to fetch institution {inst_id}: {response.status_code}"
            )

        return self._parse_institution_details(response.text)

    def _parse_institution_details(self, html: str) -> dict[str, Any]:
        """Parse institution debt details HTML.

        Similar structure to ANAF obligations - looks for amount fields
        and income type labels.
        """
        result: dict[str, Any] = {
            "has_debts": False,
            "total": 0.0,
            "debts": [],
        }

        # Check for "no debts" messages
        no_debt_patterns = [
            "Nu există obligații",
            "nu exista obligatii",
            "Nu există debite",
            "nu exista debite",
            "Nu datorați",
            "nu datorati",
        ]
        for pattern in no_debt_patterns:
            if pattern.lower() in html.lower():
                return result

        debts = []

        # Look for amount elements: suma_venit_{id}
        amount_matches = re.findall(
            r"id=['\"]suma_venit_(\d+)['\"][^>]*>([\d.,]+)</",
            html,
        )
        if amount_matches:
            result["has_debts"] = True
            for venit_id, amount_str in amount_matches:
                amount = self._parse_amount(amount_str)
                name = f"Debit {venit_id}"

                # Try to find label
                label_match = re.search(
                    rf"showDetaliiVenit\([^,]*,\s*\d+\s*,\s*{venit_id}\s*\)"
                    rf"[^>]*>([^<]+)<",
                    html,
                )
                if label_match:
                    name = label_match.group(1).strip()

                debts.append(
                    {"id": venit_id, "name": name, "amount": amount}
                )
                result["total"] += amount

        # Check TotalGeneral
        total_match = re.search(
            r"id=['\"]TotalGeneral['\"][^>]*value=['\"]([^'\"]+)['\"]",
            html,
        )
        if total_match:
            total_val = self._parse_amount(total_match.group(1))
            if total_val > 0:
                result["has_debts"] = True
                if not debts:
                    result["total"] = total_val
                    debts.append(
                        {
                            "id": "unknown",
                            "name": "Obligații instituție",
                            "amount": total_val,
                        }
                    )

        # Look for table rows with amounts as fallback
        if not debts:
            row_pattern = re.findall(
                r"<tr[^>]*>.*?<td[^>]*>([^<]+)</td>.*?<td[^>]*>"
                r"([\d.,]+)\s*(?:RON|lei)?</td>",
                html,
                re.DOTALL | re.IGNORECASE,
            )
            for name, amount_str in row_pattern:
                name = name.strip()
                amount = self._parse_amount(amount_str)
                if amount > 0 and name:
                    result["has_debts"] = True
                    debts.append({"name": name, "amount": amount})
                    result["total"] += amount

        result["debts"] = debts
        return result

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _parse_amount(amount_str: str) -> float:
        """Parse a Romanian-formatted amount string to float.

        Handles formats like:
        - "1.234,56" (Romanian format: dots for thousands, comma for decimal)
        - "1234.56" (standard format)
        - "1234,56" (comma decimal, no thousands)
        - "0" / empty
        """
        if not amount_str:
            return 0.0

        amount_str = amount_str.strip()

        # Remove currency symbols and whitespace
        amount_str = (
            amount_str.replace("RON", "")
            .replace("Lei", "")
            .replace("lei", "")
            .strip()
        )

        if not amount_str:
            return 0.0

        try:
            # Check if it's Romanian format (has both dots and commas)
            if "." in amount_str and "," in amount_str:
                # Romanian: 1.234,56 -> 1234.56
                amount_str = amount_str.replace(".", "").replace(",", ".")
            elif "," in amount_str:
                # Comma as decimal separator: 1234,56 -> 1234.56
                amount_str = amount_str.replace(",", ".")

            return float(amount_str)
        except ValueError:
            _LOGGER.warning("Failed to parse amount: '%s'", amount_str)
            return 0.0
