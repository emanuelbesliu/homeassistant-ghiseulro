"""API client for Ghiseul.ro.

Copyright (c) 2026 Emanuel Besliu
Licensed under the MIT License

This integration was developed through reverse engineering of the
ghiseul.ro platform and is not affiliated with or endorsed by
Ghiseul.ro or the Romanian Government.

Architecture overview:
  Phase 1 - Cloudflare bypass via FlareSolverr:
    FlareSolverr (headless Firefox) navigates to the ghiseul.ro base URL,
    solves the Cloudflare Managed Challenge (Turnstile), and returns
    clearance cookies + the User-Agent string it used.

  Phase 2 - Data fetching via requests.Session:
    A plain requests.Session is configured with the clearance cookies and
    the exact same User-Agent.  All subsequent HTTP calls (login, ANAF
    obligations, institution debts) go through this session.

    CRITICAL: The User-Agent MUST match the one FlareSolverr used.
    If they don't match, Cloudflare will re-issue the challenge.

  Cookie refresh:
    Cloudflare clearance cookies expire (typically 15-30 minutes).
    Every HTTP request is wrapped by _request_with_clearance() which
    detects 403 / "Just a moment..." challenge pages.  On detection it:
      1. Re-solves the challenge via FlareSolverr
      2. Re-authenticates with ghiseul.ro (session is lost on new clearance)
      3. Retries the original request once
    At most one re-solve per request to prevent infinite loops.

The API flow:
1. POST /login/process with username+password (AJAX, x-www-form-urlencoded)
   - Session cookie is managed automatically by requests.Session
2. GET /debite/institutii (AJAX) -> HTML fragment listing enrolled institutions
3. GET /debite/get-institution-details/id_inst/{id} -> institution debt details
4. GET /debite/anaf -> full page with ANAF section (contains CUI, tipPers)
5. GET /debite/incarca-debite-anaf (AJAX) -> HTML fragment with ANAF obligations

All HTTP calls are synchronous (requests-based) and dispatched to an
executor via asyncio.to_thread() to avoid blocking the HA event loop.
"""
from __future__ import annotations

import asyncio
import logging
import re
from typing import Any

import requests

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
    DEFAULT_FLARESOLVERR_URL,
    FLARESOLVERR_MAX_TIMEOUT,
    FLARESOLVERR_TABS_TILL_VERIFY,
)

_LOGGER = logging.getLogger(__name__)


class FlareSolverrError(Exception):
    """Raised when FlareSolverr fails to solve the challenge."""


class CloudflareChallengeDetected(Exception):
    """Raised when a response contains a Cloudflare challenge page."""


class GhiseulRoAPI:
    """API client for the Ghiseul.ro platform.

    Uses FlareSolverr to bypass Cloudflare Managed Challenge, then a
    plain requests.Session with the extracted clearance cookies and
    matching User-Agent for all subsequent HTTP calls.

    All HTTP calls run in a thread-pool executor so the HA event loop
    is never blocked.
    """

    def __init__(
        self,
        username: str,
        password: str,
        flaresolverr_url: str = DEFAULT_FLARESOLVERR_URL,
    ) -> None:
        """Initialize the API client."""
        self._username = username
        self._password = password
        self._flaresolverr_url = flaresolverr_url
        self._session: requests.Session | None = None
        self._authenticated = False
        self._flaresolverr_session_id: str | None = None

    # ------------------------------------------------------------------
    # Session management
    # ------------------------------------------------------------------

    def _get_session(self) -> requests.Session:
        """Get or create the requests session."""
        if self._session is None:
            self._session = requests.Session()
        return self._session

    def _reset_session(self) -> None:
        """Close and discard the current requests session.

        Called when clearance cookies expire and a fresh session is needed.
        """
        if self._session is not None:
            self._session.close()
            self._session = None
        self._authenticated = False

    async def async_close(self) -> None:
        """Close the underlying requests session and FlareSolverr session."""
        if self._session is not None:
            self._session.close()
            self._session = None
        # Destroy FlareSolverr session if we created one
        if self._flaresolverr_session_id is not None:
            try:
                await asyncio.to_thread(self._destroy_flaresolverr_session)
            except Exception:
                _LOGGER.debug(
                    "Failed to destroy FlareSolverr session %s (non-critical)",
                    self._flaresolverr_session_id,
                )
            self._flaresolverr_session_id = None

    # ------------------------------------------------------------------
    # Cloudflare challenge detection
    # ------------------------------------------------------------------

    @staticmethod
    def _is_cloudflare_challenge(response: requests.Response) -> bool:
        """Detect whether a response is a Cloudflare challenge page.

        Checks for:
        - HTTP 403 with Cf-Mitigated header
        - "Just a moment..." in the body (Cloudflare challenge title)
        - Server: cloudflare header combined with 403
        """
        if response.status_code == 403:
            # Definitive: Cloudflare mitigation header
            if response.headers.get("Cf-Mitigated"):
                return True
            # Server header check
            server = response.headers.get("Server", "").lower()
            if "cloudflare" in server:
                return True

        # Body check - works for any status code (some challenges return 503)
        body_lower = response.text[:2000].lower()
        if "just a moment" in body_lower and (
            "cloudflare" in body_lower
            or response.headers.get("Server", "").lower() == "cloudflare"
        ):
            return True

        return False

    # ------------------------------------------------------------------
    # Request wrapper with automatic clearance refresh
    # ------------------------------------------------------------------

    def _request_with_clearance(
        self,
        method: str,
        url: str,
        _is_retry: bool = False,
        **kwargs: Any,
    ) -> requests.Response:
        """Make an HTTP request, automatically refreshing clearance on challenge.

        If the response is a Cloudflare challenge page:
        1. Re-solve the challenge via FlareSolverr
        2. Re-authenticate with ghiseul.ro (old session is invalidated)
        3. Retry the original request once

        The _is_retry flag prevents infinite loops — at most one re-solve
        per request.
        """
        session = self._get_session()
        response = session.request(method, url, **kwargs)

        if self._is_cloudflare_challenge(response):
            if _is_retry:
                _LOGGER.error(
                    "Cloudflare challenge detected on retry for %s. "
                    "Giving up — FlareSolverr clearance did not stick.",
                    url,
                )
                raise CloudflareChallengeDetected(
                    f"Cloudflare challenge on {url} even after re-solve"
                )

            _LOGGER.warning(
                "Cloudflare challenge detected on %s (status=%s). "
                "Clearance cookies likely expired. Re-solving...",
                url,
                response.status_code,
            )

            # Reset everything and re-establish clearance + auth
            self._refresh_clearance_and_auth()

            # Retry the original request
            return self._request_with_clearance(
                method, url, _is_retry=True, **kwargs
            )

        return response

    def _refresh_clearance_and_auth(self) -> None:
        """Re-solve Cloudflare challenge and re-authenticate.

        Called when clearance cookies have expired mid-session.
        Resets the requests session, obtains fresh clearance from
        FlareSolverr, and logs back in to ghiseul.ro.
        """
        _LOGGER.info("Refreshing Cloudflare clearance and re-authenticating")

        # Tear down old session (stale cookies)
        self._reset_session()

        # Phase 1: Solve Cloudflare challenge
        cookies, user_agent = self._solve_cloudflare_challenge()

        # Phase 2: Apply clearance to fresh session
        self._apply_clearance_to_session(cookies, user_agent)

        # Phase 3: Re-authenticate
        session = self._get_session()

        # Verify clearance works
        response = session.get(f"{BASE_URL}/")
        if self._is_cloudflare_challenge(response):
            raise FlareSolverrError(
                "Fresh clearance cookies from FlareSolverr did not "
                "bypass Cloudflare after refresh."
            )

        # Login
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

        response = session.post(LOGIN_URL, data=login_data, headers=headers)
        if response.status_code != 200:
            raise Exception(
                f"Re-login failed after clearance refresh: {response.status_code}"
            )

        # Verify login
        response = session.post(
            IS_LOGGED_IN_URL,
            headers={"X-Requested-With": "XMLHttpRequest"},
        )
        body = response.text.strip() if response.status_code == 200 else ""
        if body != "1":
            raise Exception(
                f"Re-login verification failed after clearance refresh: "
                f"este-logat returned '{body[:50]}'"
            )

        self._authenticated = True
        _LOGGER.info(
            "Clearance refresh complete — re-authenticated successfully"
        )

    # ------------------------------------------------------------------
    # FlareSolverr interaction
    # ------------------------------------------------------------------

    def _call_flaresolverr(self, payload: dict[str, Any]) -> dict[str, Any]:
        """Make a POST request to the FlareSolverr API.

        Returns the parsed JSON response.
        Raises FlareSolverrError on failure.
        """
        try:
            _LOGGER.debug(
                "FlareSolverr request: cmd=%s, url=%s",
                payload.get("cmd"),
                payload.get("url", "N/A"),
            )
            resp = requests.post(
                self._flaresolverr_url,
                json=payload,
                timeout=180,
            )
            resp.raise_for_status()
            data = resp.json()
            _LOGGER.debug(
                "FlareSolverr response: status=%s, message=%s",
                data.get("status"),
                data.get("message", ""),
            )
            if data.get("status") != "ok":
                raise FlareSolverrError(
                    f"FlareSolverr returned status '{data.get('status')}': "
                    f"{data.get('message', 'unknown error')}"
                )
            return data
        except requests.RequestException as err:
            raise FlareSolverrError(
                f"Failed to communicate with FlareSolverr at "
                f"{self._flaresolverr_url}: {err}"
            ) from err

    def _create_flaresolverr_session(self) -> str:
        """Create a persistent FlareSolverr session.

        Returns the session ID.
        """
        data = self._call_flaresolverr({"cmd": "sessions.create"})
        session_id = data.get("session")
        if not session_id:
            raise FlareSolverrError(
                "FlareSolverr did not return a session ID"
            )
        _LOGGER.debug("Created FlareSolverr session: %s", session_id)
        return session_id

    def _destroy_flaresolverr_session(self) -> None:
        """Destroy the FlareSolverr session."""
        if self._flaresolverr_session_id:
            try:
                self._call_flaresolverr({
                    "cmd": "sessions.destroy",
                    "session": self._flaresolverr_session_id,
                })
                _LOGGER.debug(
                    "Destroyed FlareSolverr session: %s",
                    self._flaresolverr_session_id,
                )
            except FlareSolverrError:
                pass

    def _solve_cloudflare_challenge(self) -> tuple[list[dict], str]:
        """Use FlareSolverr to solve the Cloudflare challenge on ghiseul.ro.

        Returns:
            Tuple of (cookies_list, user_agent_string)

        The cookies list contains dicts with at minimum 'name' and 'value' keys.
        """
        # Create a persistent session so cookies are retained
        if self._flaresolverr_session_id is None:
            self._flaresolverr_session_id = self._create_flaresolverr_session()

        _LOGGER.info(
            "Solving Cloudflare challenge for %s via FlareSolverr", BASE_URL
        )

        data = self._call_flaresolverr({
            "cmd": "request.get",
            "url": f"{BASE_URL}/",
            "session": self._flaresolverr_session_id,
            "maxTimeout": FLARESOLVERR_MAX_TIMEOUT,
            "tabs_till_verify": FLARESOLVERR_TABS_TILL_VERIFY,
        })

        solution = data.get("solution", {})
        status = solution.get("status", 0)
        cookies = solution.get("cookies", [])
        user_agent = solution.get("userAgent", "")
        response_url = solution.get("url", "")

        _LOGGER.debug(
            "FlareSolverr challenge result: status=%s, url=%s, "
            "cookies=%d, userAgent=%.60s...",
            status,
            response_url,
            len(cookies),
            user_agent,
        )

        if status == 403 or not cookies:
            # FlareSolverr itself couldn't bypass the challenge
            response_html = solution.get("response", "")
            snippet = response_html[:500] if response_html else "(empty)"
            raise FlareSolverrError(
                f"FlareSolverr could not solve Cloudflare challenge "
                f"(status={status}). Response snippet: {snippet}"
            )

        if not user_agent:
            raise FlareSolverrError(
                "FlareSolverr did not return a User-Agent string"
            )

        _LOGGER.info(
            "Cloudflare challenge solved. Got %d cookies.", len(cookies)
        )
        return cookies, user_agent

    def _apply_clearance_to_session(
        self, cookies: list[dict], user_agent: str
    ) -> None:
        """Apply FlareSolverr clearance cookies and UA to requests.Session.

        The User-Agent MUST match what FlareSolverr used, otherwise
        Cloudflare will re-issue the challenge.
        """
        session = self._get_session()

        # Set the matching User-Agent
        session.headers.update({
            "User-Agent": user_agent,
        })
        _LOGGER.debug("Set User-Agent: %.80s...", user_agent)

        # Apply all cookies from FlareSolverr
        for cookie in cookies:
            name = cookie.get("name", "")
            value = cookie.get("value", "")
            domain = cookie.get("domain", "")
            path = cookie.get("path", "/")

            if not name or not value:
                continue

            # Clean domain - remove leading dot if present for setting
            cookie_domain = domain.lstrip(".")

            session.cookies.set(
                name,
                value,
                domain=cookie_domain,
                path=path,
            )
            _LOGGER.debug(
                "Applied cookie: %s=%s... (domain=%s, path=%s)",
                name,
                value[:20],
                domain,
                path,
            )

        _LOGGER.debug(
            "Session cookies after applying clearance: %s",
            list(session.cookies.keys()),
        )

    async def async_test_flaresolverr(self) -> bool:
        """Test connectivity to FlareSolverr (for config flow validation).

        Returns True if FlareSolverr is reachable and responding.
        """
        try:
            data = await asyncio.to_thread(
                self._call_flaresolverr, {"cmd": "sessions.list"}
            )
            return data.get("status") == "ok"
        except FlareSolverrError as err:
            _LOGGER.error("FlareSolverr connectivity test failed: %s", err)
            return False

    # ------------------------------------------------------------------
    # Authentication
    # ------------------------------------------------------------------

    async def authenticate(self) -> bool:
        """Authenticate with the Ghiseul.ro platform (async wrapper)."""
        return await asyncio.to_thread(self._authenticate_sync)

    def _authenticate_sync(self) -> bool:
        """Authenticate with the Ghiseul.ro platform.

        The authentication flow:
        1. Use FlareSolverr to solve Cloudflare challenge and get cookies
        2. Apply clearance cookies + User-Agent to requests session
        3. POST /login/process with username and password
        4. Verify session by checking /index/este-logat
        """
        try:
            # Phase 1: Solve Cloudflare challenge via FlareSolverr
            _LOGGER.debug(
                "Phase 1: Solving Cloudflare challenge via FlareSolverr"
            )
            cookies, user_agent = self._solve_cloudflare_challenge()

            # Phase 2: Apply clearance to session and authenticate
            _LOGGER.debug(
                "Phase 2: Applying clearance cookies to requests session"
            )
            self._apply_clearance_to_session(cookies, user_agent)

            session = self._get_session()

            # Step 1: Hit the base URL through the session to verify
            # clearance cookies work
            _LOGGER.debug(
                "Step 1: Verifying clearance by loading base URL: %s",
                BASE_URL,
            )
            response = session.get(f"{BASE_URL}/")
            _LOGGER.debug(
                "Step 1 result: status=%s, url=%s, body_length=%d",
                response.status_code,
                response.url,
                len(response.text),
            )

            if self._is_cloudflare_challenge(response):
                _LOGGER.error(
                    "Clearance cookies did not bypass Cloudflare. "
                    "Status=%s, Headers: %s, Body snippet: %.300s",
                    response.status_code,
                    dict(response.headers),
                    response.text[:300],
                )
                raise FlareSolverrError(
                    "Clearance cookies from FlareSolverr did not bypass "
                    "Cloudflare. The challenge may have changed."
                )

            # Step 2: POST login
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

            _LOGGER.debug("Step 2: Posting login to %s", LOGIN_URL)
            response = session.post(
                LOGIN_URL,
                data=login_data,
                headers=headers,
            )
            _LOGGER.debug(
                "Step 2 result: status=%s, url=%s, body_length=%d",
                response.status_code,
                response.url,
                len(response.text),
            )
            _LOGGER.debug(
                "Step 2 response headers: %s",
                dict(response.headers),
            )
            _LOGGER.debug(
                "Step 2 cookies: %s",
                list(session.cookies.keys()),
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
                "Step 2 login response body: %.300s", response.text[:300]
            )

            # Step 3: Verify we are logged in
            _LOGGER.debug("Step 3: Verifying login via %s", IS_LOGGED_IN_URL)
            response = session.post(
                IS_LOGGED_IN_URL,
                headers={"X-Requested-With": "XMLHttpRequest"},
            )
            _LOGGER.debug(
                "Step 3 result: status=%s, body='%s'",
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

        except FlareSolverrError:
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

        Uses _request_with_clearance() so expired Cloudflare cookies
        are automatically refreshed.
        """
        result: dict[str, Any] = {
            "has_obligations": False,
            "total": 0.0,
            "obligations": [],
            "cui": "",
            "message": "",
        }

        try:
            # Step 1: Load ANAF page to establish context and extract CUI
            response = self._request_with_clearance(
                "GET",
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
            response = self._request_with_clearance(
                "GET",
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

        Uses _request_with_clearance() so expired Cloudflare cookies
        are automatically refreshed.
        """
        institutions: dict[str, dict[str, Any]] = {}

        try:
            # Step 1: Get institution list
            ajax_headers = {
                "X-Requested-With": "XMLHttpRequest",
                "Referer": DEBITE_URL,
            }

            response = self._request_with_clearance(
                "GET",
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
        url = DEBITE_INSTITUTION_DETAILS_URL.format(id_inst=inst_id)
        ajax_headers = {
            "X-Requested-With": "XMLHttpRequest",
            "Referer": DEBITE_URL,
        }

        response = self._request_with_clearance(
            "GET", url, headers=ajax_headers
        )
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
