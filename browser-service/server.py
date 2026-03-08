"""
ghiseul-browser: A lightweight browser microservice for ghiseul.ro.

Uses nodriver (stealthy Chrome automation) with a persistent browser instance
to bypass Cloudflare Managed Challenge and scrape debt/tax data.

All requests share the same browser in a single asyncio event loop,
keeping cookies and session state alive between calls.
"""

import asyncio
import hashlib
import json
import logging
import os
import re
import shutil
import sys
import tempfile
import time
from typing import Optional

import nodriver as nd
from aiohttp import web

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
HOST = os.environ.get("HOST", "0.0.0.0")
PORT = int(os.environ.get("PORT", 8192))
LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO").upper()
HEADLESS = os.environ.get("HEADLESS", "true").lower() == "true"

BASE_URL = "https://www.ghiseul.ro/ghiseul/public"
LOGIN_URL = f"{BASE_URL}/login/process"
DEBTS_URL = f"{BASE_URL}/debite"
INSTITUTIONS_URL = f"{BASE_URL}/debite/institutii"
INSTITUTION_DETAILS_URL = f"{BASE_URL}/debite/get-institution-details/id_inst"
ANAF_URL = f"{BASE_URL}/debite/anaf"
ANAF_DEBTS_URL = f"{BASE_URL}/debite/incarca-debite-anaf"
ESTE_LOGAT_URL = f"{BASE_URL}/index/este-logat"
LOGOUT_URL = f"{BASE_URL}/login/logout"
TAXES_URL = f"{BASE_URL}/taxe"

CF_CHALLENGE_TITLES = ["Just a moment...", "DDoS-Guard"]
CF_CHALLENGE_SELECTORS = [
    "#cf-challenge-running", ".ray_id", ".attack-box",
    "#cf-please-wait", "#challenge-spinner", "#trk_jschal_js",
    "#turnstile-wrapper", ".lds-ring", ".loading-spinner",
    ".main-wrapper",
]
ACCESS_DENIED_TITLES = ["Access denied", "Attention Required! | Cloudflare"]

SHORT_TIMEOUT = 3
CF_SOLVE_TIMEOUT = 60

logger = logging.getLogger("ghiseul-browser")

# ---------------------------------------------------------------------------
# Global browser state
# ---------------------------------------------------------------------------
browser: Optional[nd.Browser] = None
browser_lock = asyncio.Lock()
xvfb_display = None


def create_cloudflare_extension() -> str:
    """Create the Turnstile Patcher extension that fixes screenX/screenY."""
    manifest_json = """{
        "manifest_version": 3,
        "name": "Turnstile Patcher",
        "version": "2.1",
        "content_scripts": [{
            "js": ["./script.js"],
            "matches": ["<all_urls>"],
            "run_at": "document_start",
            "all_frames": true,
            "world": "MAIN"
        }]
    }"""
    script_js = """
    Object.defineProperty(MouseEvent.prototype, 'screenX', {
        get: function () { return this.clientX + window.screenX; }
    });
    Object.defineProperty(MouseEvent.prototype, 'screenY', {
        get: function () { return this.clientY + window.screenY; }
    });
    """
    ext_dir = tempfile.mkdtemp(prefix="cf_ext_")
    with open(os.path.join(ext_dir, "manifest.json"), "w") as f:
        f.write(manifest_json)
    with open(os.path.join(ext_dir, "script.js"), "w") as f:
        f.write(script_js)
    return ext_dir


def start_xvfb():
    """Start virtual X display for head-full Chrome in headless environments."""
    global xvfb_display
    if xvfb_display is None and os.name != "nt":
        try:
            from xvfbwrapper import Xvfb
            xvfb_display = Xvfb()
            xvfb_display.start()
            logger.info("Virtual display started")
        except ImportError:
            logger.warning("xvfbwrapper not installed, assuming display available")


async def get_browser() -> nd.Browser:
    """Get or create the persistent browser instance."""
    global browser
    async with browser_lock:
        if browser is not None:
            # Check if browser process is still alive
            try:
                proc = getattr(browser, "_process", None) or getattr(browser, "get_process", None)
                if proc is not None:
                    returncode = getattr(proc, "returncode", None)
                    if returncode is None:
                        # Process still running
                        return browser
                    logger.warning("Browser process died (rc=%s), recreating...", returncode)
                else:
                    # No process attribute found; check if we have open tabs
                    if browser.tabs:
                        return browser
                    logger.warning("Browser has no tabs, recreating...")
            except Exception as e:
                logger.warning("Browser health check failed: %s, recreating...", e)
            browser = None

        logger.info("Creating new browser instance...")
        if HEADLESS:
            start_xvfb()

        options = nd.Config()
        options.sandbox = False
        options.add_argument("--disable-software-rasterizer")
        options.add_argument("--disable-gpu")
        options.add_argument("--ignore-certificate-errors")
        options.add_argument("--ignore-ssl-errors")
        options.add_argument("--use-gl=swiftshader")
        options.add_argument("--no-first-run")
        options.add_argument("--no-default-browser-check")

        language = os.environ.get("LANG", "en-US")
        options.lang = language

        # Add CF Turnstile Patcher extension
        ext_dir = create_cloudflare_extension()
        options.add_extension(os.path.abspath(ext_dir))

        browser = await nd.Browser.create(config=options)
        shutil.rmtree(ext_dir, ignore_errors=True)
        logger.info("Browser created successfully")
        return browser


async def click_cf_verify(tab: nd.Tab):
    """Attempt to click the Cloudflare verification checkbox."""
    try:
        logger.debug("Looking for CF captcha...")
        await tab.wait(2)
        await tab
        cf_element = await tab.find(text="cf-chl-widget-", timeout=SHORT_TIMEOUT)
        if cf_element:
            logger.debug("CF captcha found, looking for iframe...")
            await tab.browser.update_targets()
            cf_tab = next(
                (t for t in tab.browser.targets
                 if "challenges.cloudflare.com" in t.url),
                None,
            )
            if cf_tab is None:
                raise ValueError("Captcha iframe not found")
            cf_tab.websocket_url = cf_tab.websocket_url.replace("iframe", "page")
            cf_checkbox = await cf_tab.find(text="checkbox", timeout=SHORT_TIMEOUT)
            await cf_checkbox.mouse_click()
            logger.debug("CF checkbox clicked")
    except Exception as e:
        logger.debug(f"CF captcha not found or click failed: {e}")
    await asyncio.sleep(2)


async def solve_cf_challenge(tab: nd.Tab, timeout: float = CF_SOLVE_TIMEOUT):
    """Wait for and solve Cloudflare challenge on the given tab."""
    await tab.wait(1)
    await tab

    # Check page title for challenge
    page_title = tab.target.title or ""

    # Check for access denied
    for title in ACCESS_DENIED_TITLES:
        if title.lower() == page_title.lower():
            raise Exception(f"Cloudflare blocked: {page_title}")

    # Detect challenge
    challenge_found = False
    for title in CF_CHALLENGE_TITLES:
        if title.lower() == page_title.lower():
            challenge_found = True
            logger.info(f"CF challenge detected: {page_title}")
            break

    if not challenge_found:
        doc = await tab.send(nd.cdp.dom.get_document(-1, True))
        for selector in CF_CHALLENGE_SELECTORS:
            el = await tab.query_selector(selector=selector, _node=doc)
            if el is not None:
                challenge_found = True
                logger.info(f"CF challenge detected via selector: {selector}")
                break

    if not challenge_found:
        logger.info("No CF challenge detected")
        return

    # Solve the challenge
    start_time = time.time()
    attempt = 0
    while time.time() - start_time < timeout:
        attempt += 1
        await tab.wait(1)

        # Wait for title to change from challenge titles
        current_title = tab.target.title or ""
        if current_title.lower() in [t.lower() for t in CF_CHALLENGE_TITLES]:
            # Still on challenge page, try clicking verify
            if attempt % 3 == 0:
                await click_cf_verify(tab)
            continue

        # Title changed — check if selectors are gone too
        doc = await tab.send(nd.cdp.dom.get_document(-1, True))
        selectors_present = False
        for selector in CF_CHALLENGE_SELECTORS:
            el = await tab.query_selector(selector=selector, _node=doc)
            if el is not None:
                selectors_present = True
                break

        if not selectors_present:
            # Wait for redirect to finish
            try:
                await tab
            except Exception:
                pass
            logger.info(f"CF challenge solved in {time.time() - start_time:.1f}s")
            return

    raise TimeoutError(f"CF challenge not solved after {timeout}s")


async def navigate_and_solve(url: str) -> nd.Tab:
    """Navigate to URL, solve CF challenge if present, return the tab."""
    drv = await get_browser()
    tab = await drv.get(url)
    await solve_cf_challenge(tab)
    return tab


def _safe_evaluate_result(result) -> str:
    """Safely convert a tab.evaluate() result to a string.

    nodriver returns an ExceptionDetails object (not a string) when JS
    evaluation fails.  Detect that and convert to a readable error string.
    """
    if result is None:
        return ""
    # ExceptionDetails is a CDP type; its class name is the simplest check
    type_name = type(result).__name__
    if type_name == "ExceptionDetails" or "ExceptionDetails" in type_name:
        # Try to pull a human-readable message out of the object
        text = getattr(result, "text", None) or str(result)
        raise RuntimeError(f"JS evaluation error: {text}")
    if isinstance(result, str):
        return result
    return str(result)


async def execute_js(tab: nd.Tab, script: str) -> str:
    """Execute JavaScript in the tab and return the result."""
    result = await tab.evaluate(script)
    return _safe_evaluate_result(result)


async def ajax_get(tab: nd.Tab, url: str) -> str:
    """Perform an AJAX GET from the browser and return response text."""
    js = f"""
    (async () => {{
        const resp = await fetch("{url}", {{
            method: "GET",
            headers: {{
                "X-Requested-With": "XMLHttpRequest",
            }},
            credentials: "same-origin"
        }});
        return await resp.text();
    }})()
    """
    result = await tab.evaluate(js, await_promise=True)
    return _safe_evaluate_result(result)


async def ajax_post(tab: nd.Tab, url: str, data: dict) -> str:
    """Perform an AJAX POST from the browser and return response text."""
    # Build URL-encoded body
    pairs = "&".join(f"{k}={v}" for k, v in data.items())
    js = f"""
    (async () => {{
        const resp = await fetch("{url}", {{
            method: "POST",
            headers: {{
                "X-Requested-With": "XMLHttpRequest",
                "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8"
            }},
            credentials: "same-origin",
            body: "{pairs}"
        }});
        return await resp.text();
    }})()
    """
    result = await tab.evaluate(js, await_promise=True)
    return _safe_evaluate_result(result)


def _build_login_js(username: str, password: str) -> str:
    """Build JavaScript that logs in via the page's CryptoJS.

    Extracts the default parolaHmac from the page's own verifica()
    function so we never need to hardcode it.
    """
    return """
    (async () => {
        // Wait for CryptoJS to be available (loaded by the page)
        for (let i = 0; i < 30; i++) {
            if (typeof CryptoJS !== 'undefined' && CryptoJS.MD5 && CryptoJS.HmacSHA1) break;
            await new Promise(r => setTimeout(r, 500));
        }
        if (typeof CryptoJS === 'undefined') {
            throw new Error('CryptoJS not available after 15s');
        }

        // Determine HMAC key: use server-provided parolaHmac if set,
        // otherwise extract the default from verifica() source code.
        let hmacKey = (typeof parolaHmac !== 'undefined' && parolaHmac)
            ? parolaHmac
            : null;
        if (!hmacKey) {
            try {
                const src = verifica.toString();
                const m = src.match(/parolaHmac\\s*=\\s*['\"]([a-f0-9]+)['\"]/);
                if (m) hmacKey = m[1];
            } catch(e) {}
        }
        if (!hmacKey) {
            throw new Error('Could not determine parolaHmac from page');
        }

        // Hash: HmacSHA1(MD5(password).hex, hmacKey).hex
        const md5Hash = CryptoJS.MD5(PLACEHOLDER_PWD).toString(CryptoJS.enc.Hex);
        const finalHash = CryptoJS.HmacSHA1(md5Hash, hmacKey).toString(CryptoJS.enc.Hex);

        const resp = await fetch(PLACEHOLDER_URL, {
            method: "POST",
            headers: {
                "X-Requested-With": "XMLHttpRequest",
                "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8"
            },
            credentials: "same-origin",
            body: "username=" + encodeURIComponent(PLACEHOLDER_USER) + "&password=" + encodeURIComponent(finalHash)
        });
        const text = await resp.text();

        // Update parolaHmac if server returned a new one
        try {
            const parsed = JSON.parse(text);
            if (parsed.parolaHmac) {
                parolaHmac = parsed.parolaHmac;
            }
        } catch(e) {}

        return text;
    })()
    """.replace("PLACEHOLDER_PWD", json.dumps(password)) \
       .replace("PLACEHOLDER_URL", json.dumps(LOGIN_URL)) \
       .replace("PLACEHOLDER_USER", json.dumps(username))


# ---------------------------------------------------------------------------
# API Handlers
# ---------------------------------------------------------------------------

async def handle_health(request: web.Request) -> web.Response:
    """Health check endpoint."""
    return web.json_response({"status": "ok"})


async def handle_login(request: web.Request) -> web.Response:
    """
    POST /login
    Body: {"username": "...", "password": "..."}

    Navigates to ghiseul.ro, solves CF, logs in.
    Uses the page's CryptoJS to hash: HmacSHA1(MD5(password), parolaHmac).
    Returns: {"status": "ok", "logged_in": true/false, "response": "..."}
    """
    try:
        body = await request.json()
        username = body.get("username")
        password = body.get("password")
        if not username or not password:
            return web.json_response(
                {"status": "error", "message": "username and password required"},
                status=400,
            )

        # Navigate to login page to establish CF cookies
        logger.info("Navigating to login page...")
        tab = await navigate_and_solve(f"{BASE_URL}/")

        # Use the page's own CryptoJS + login flow via shared helper.
        logger.info("Performing login...")
        login_js = _build_login_js(username, password)

        raw_result = await tab.evaluate(login_js, await_promise=True)
        login_response = _safe_evaluate_result(raw_result)
        logger.info(f"Login response: {login_response[:100] if login_response else 'empty'}")

        # Check if logged in
        is_logged = await ajax_post(tab, ESTE_LOGAT_URL, {})
        logged_in = is_logged.strip() == "1"
        logger.info(f"Logged in: {logged_in}")

        # Keep the tab open for subsequent requests
        return web.json_response({
            "status": "ok",
            "logged_in": logged_in,
            "login_response": login_response,
        })
    except Exception as e:
        logger.error(f"Login error: {e}", exc_info=True)
        return web.json_response(
            {"status": "error", "message": str(e)}, status=500
        )


async def handle_check_login(request: web.Request) -> web.Response:
    """
    GET /check-login
    Check if the browser session is currently logged in.
    """
    try:
        drv = await get_browser()
        # Use the most recent tab
        tab = drv.main_tab
        if tab is None:
            return web.json_response({
                "status": "ok", "logged_in": False,
                "message": "No active tab"
            })

        is_logged = await ajax_post(tab, ESTE_LOGAT_URL, {})
        logged_in = is_logged.strip() == "1"
        return web.json_response({"status": "ok", "logged_in": logged_in})
    except Exception as e:
        logger.error(f"Check login error: {e}", exc_info=True)
        return web.json_response(
            {"status": "error", "message": str(e)}, status=500
        )


async def handle_debts(request: web.Request) -> web.Response:
    """
    GET /debts
    Fetches all institution debts.
    Returns: {
        "status": "ok",
        "institutions": [
            {"id": "123", "name": "...", "details_html": "...", "total": "0,00"},
            ...
        ]
    }
    """
    try:
        drv = await get_browser()
        tab = drv.main_tab
        if tab is None:
            return web.json_response(
                {"status": "error", "message": "Not logged in (no tab)"},
                status=401,
            )

        # Fetch institutions list
        logger.info("Fetching institutions list...")
        institutions_html = await ajax_get(tab, INSTITUTIONS_URL)

        if institutions_html.strip() == "SESIUNE_EXPIRATA":
            return web.json_response(
                {"status": "error", "message": "Session expired"},
                status=401,
            )

        # Parse institution IDs and names from HTML
        # Pattern: <div class="panel panel-default" id='{id}'>
        #          <div class="panel-heading"> ... institution name ...
        institutions = []
        id_pattern = re.compile(
            r'<div\s+class="panel\s+panel-default"\s+id=[\'"](\d+)[\'"]',
            re.IGNORECASE,
        )
        heading_pattern = re.compile(
            r'<div\s+class="panel-heading"[^>]*>(.*?)</div>',
            re.IGNORECASE | re.DOTALL,
        )

        ids = id_pattern.findall(institutions_html)
        headings = heading_pattern.findall(institutions_html)

        for i, inst_id in enumerate(ids):
            name = ""
            if i < len(headings):
                # Strip HTML tags from heading
                name = re.sub(r"<[^>]+>", "", headings[i]).strip()

            # Fetch details for this institution
            logger.info(f"Fetching details for institution {inst_id}: {name}")
            details_html = await ajax_get(
                tab, f"{INSTITUTION_DETAILS_URL}/{inst_id}"
            )

            if details_html.strip() == "SESIUNE_EXPIRATA":
                return web.json_response(
                    {"status": "error", "message": "Session expired"},
                    status=401,
                )

            # Extract total from details
            total_match = re.search(
                r'id="TotalGeneral"\s+value="([^"]*)"', details_html
            )
            total = total_match.group(1) if total_match else "0,00"

            institutions.append({
                "id": inst_id,
                "name": name,
                "total": total,
                "details_html": details_html,
            })

        return web.json_response({
            "status": "ok",
            "institutions": institutions,
            "institutions_html": institutions_html,
        })
    except Exception as e:
        logger.error(f"Debts error: {e}", exc_info=True)
        return web.json_response(
            {"status": "error", "message": str(e)}, status=500
        )


async def handle_anaf(request: web.Request) -> web.Response:
    """
    GET /anaf
    Fetches ANAF (tax authority) debts.
    Returns: {"status": "ok", "anaf_html": "..."}
    """
    try:
        drv = await get_browser()
        tab = drv.main_tab
        if tab is None:
            return web.json_response(
                {"status": "error", "message": "Not logged in (no tab)"},
                status=401,
            )

        # First navigate to ANAF page to get hidden inputs (CUI, tipPers)
        logger.info("Fetching ANAF page...")
        anaf_page_html = await ajax_get(tab, ANAF_URL)

        if anaf_page_html.strip() == "SESIUNE_EXPIRATA":
            return web.json_response(
                {"status": "error", "message": "Session expired"},
                status=401,
            )

        # Fetch ANAF debts
        logger.info("Fetching ANAF debts...")
        anaf_debts_html = await ajax_get(tab, ANAF_DEBTS_URL)

        if anaf_debts_html.strip() == "SESIUNE_EXPIRATA":
            return web.json_response(
                {"status": "error", "message": "Session expired"},
                status=401,
            )

        return web.json_response({
            "status": "ok",
            "anaf_page_html": anaf_page_html,
            "anaf_debts_html": anaf_debts_html,
        })
    except Exception as e:
        logger.error(f"ANAF error: {e}", exc_info=True)
        return web.json_response(
            {"status": "error", "message": str(e)}, status=500
        )


async def handle_taxes(request: web.Request) -> web.Response:
    """
    GET /taxes
    Fetches local taxes section.
    Returns: {"status": "ok", "taxes_html": "..."}
    """
    try:
        drv = await get_browser()
        tab = drv.main_tab
        if tab is None:
            return web.json_response(
                {"status": "error", "message": "Not logged in (no tab)"},
                status=401,
            )

        logger.info("Fetching taxes page...")
        taxes_html = await ajax_get(tab, TAXES_URL)

        if taxes_html.strip() == "SESIUNE_EXPIRATA":
            return web.json_response(
                {"status": "error", "message": "Session expired"},
                status=401,
            )

        return web.json_response({
            "status": "ok",
            "taxes_html": taxes_html,
        })
    except Exception as e:
        logger.error(f"Taxes error: {e}", exc_info=True)
        return web.json_response(
            {"status": "error", "message": str(e)}, status=500
        )


async def handle_logout(request: web.Request) -> web.Response:
    """
    POST /logout
    Logs out of ghiseul.ro.
    """
    try:
        drv = await get_browser()
        tab = drv.main_tab
        if tab is not None:
            await ajax_get(tab, LOGOUT_URL)
        return web.json_response({"status": "ok", "message": "Logged out"})
    except Exception as e:
        logger.error(f"Logout error: {e}", exc_info=True)
        return web.json_response(
            {"status": "error", "message": str(e)}, status=500
        )


async def handle_scrape_all(request: web.Request) -> web.Response:
    """
    POST /scrape-all
    Body: {"username": "...", "password": "..."}

    All-in-one endpoint: login + fetch debts + ANAF + taxes.
    This is the primary endpoint for the HA integration.
    Returns all data in a single response.
    """
    try:
        body = await request.json()
        username = body.get("username")
        password = body.get("password")
        if not username or not password:
            return web.json_response(
                {"status": "error", "message": "username and password required"},
                status=400,
            )

        login_js = _build_login_js(username, password)

        # Step 1: Navigate to login page, solve CF
        logger.info("=== Starting full scrape ===")
        logger.info("Step 1: Navigating to login page...")
        tab = await navigate_and_solve(f"{BASE_URL}/")

        # Step 2: Login using browser's CryptoJS for password hashing
        logger.info("Step 2: Logging in...")

        # Debug: check page state before login
        try:
            diag = await tab.evaluate(
                "JSON.stringify({url: location.href, title: document.title, "
                "hasCrypto: typeof CryptoJS !== 'undefined', "
                "parolaHmac: typeof parolaHmac !== 'undefined' ? parolaHmac : 'UNDEFINED'})"
            )
            logger.info(f"Pre-login page state: {diag}")
        except Exception as e:
            logger.warning(f"Pre-login diagnostic failed: {e}")

        raw_result = await tab.evaluate(login_js, await_promise=True)
        login_response = _safe_evaluate_result(raw_result)
        logger.info(f"Login response: {login_response[:100] if login_response else 'empty'}")

        # Check login
        is_logged = await ajax_post(tab, ESTE_LOGAT_URL, {})
        if is_logged.strip() != "1":
            return web.json_response({
                "status": "error",
                "message": "Login failed",
                "login_response": login_response,
            }, status=401)

        # Step 3: Fetch institutions
        logger.info("Step 3: Fetching institutions...")
        institutions_html = await ajax_get(tab, INSTITUTIONS_URL)
        institutions = []

        if institutions_html.strip() != "SESIUNE_EXPIRATA":
            id_pattern = re.compile(
                r'<div\s+class="panel\s+panel-default"\s+id=[\'"](\d+)[\'"]',
                re.IGNORECASE,
            )
            heading_pattern = re.compile(
                r'<div\s+class="panel-heading"[^>]*>(.*?)</div>',
                re.IGNORECASE | re.DOTALL,
            )

            ids = id_pattern.findall(institutions_html)
            headings = heading_pattern.findall(institutions_html)

            for i, inst_id in enumerate(ids):
                name = ""
                if i < len(headings):
                    name = re.sub(r"<[^>]+>", "", headings[i]).strip()

                logger.info(f"  Fetching institution {inst_id}: {name}")
                details_html = await ajax_get(
                    tab, f"{INSTITUTION_DETAILS_URL}/{inst_id}"
                )

                total = "0,00"
                if details_html.strip() != "SESIUNE_EXPIRATA":
                    total_match = re.search(
                        r'id="TotalGeneral"\s+value="([^"]*)"', details_html
                    )
                    if total_match:
                        total = total_match.group(1)

                institutions.append({
                    "id": inst_id,
                    "name": name,
                    "total": total,
                    "details_html": details_html,
                })

        # Step 4: Fetch ANAF
        logger.info("Step 4: Fetching ANAF...")
        anaf_page_html = ""
        anaf_debts_html = ""
        try:
            anaf_page_html = await ajax_get(tab, ANAF_URL)
            if anaf_page_html.strip() != "SESIUNE_EXPIRATA":
                anaf_debts_html = await ajax_get(tab, ANAF_DEBTS_URL)
        except Exception as e:
            logger.warning(f"ANAF fetch failed: {e}")

        # Step 5: Fetch taxes
        logger.info("Step 5: Fetching taxes...")
        taxes_html = ""
        try:
            taxes_html = await ajax_get(tab, TAXES_URL)
        except Exception as e:
            logger.warning(f"Taxes fetch failed: {e}")

        # Step 6: Logout
        logger.info("Step 6: Logging out...")
        try:
            await ajax_get(tab, LOGOUT_URL)
        except Exception:
            pass

        logger.info("=== Full scrape complete ===")
        return web.json_response({
            "status": "ok",
            "logged_in": True,
            "institutions": institutions,
            "institutions_html": institutions_html,
            "anaf_page_html": anaf_page_html,
            "anaf_debts_html": anaf_debts_html,
            "taxes_html": taxes_html,
        })

    except Exception as e:
        logger.error(f"Scrape-all error: {e}", exc_info=True)
        return web.json_response(
            {"status": "error", "message": str(e)}, status=500
        )


async def handle_restart_browser(request: web.Request) -> web.Response:
    """
    POST /restart-browser
    Force-restart the browser instance (useful if it gets stuck).
    """
    global browser
    async with browser_lock:
        if browser is not None:
            try:
                browser.stop()
            except Exception:
                pass
            browser = None
    return web.json_response({"status": "ok", "message": "Browser restarted"})


async def handle_eval(request: web.Request) -> web.Response:
    """POST /eval - Evaluate JS on the current page (debug only)."""
    try:
        body = await request.json()
        js_code = body.get("js", "")
        drv = await get_browser()
        tab = drv.main_tab
        if tab is None:
            return web.json_response({"status": "error", "message": "No active tab"}, status=400)
        result = await tab.evaluate(js_code, await_promise=True)
        return web.json_response({"status": "ok", "result": str(result) if result else None})
    except Exception as e:
        return web.json_response({"status": "error", "message": str(e)}, status=500)


# ---------------------------------------------------------------------------
# Application setup
# ---------------------------------------------------------------------------

def create_app() -> web.Application:
    app = web.Application()
    app.router.add_get("/health", handle_health)
    app.router.add_post("/login", handle_login)
    app.router.add_get("/check-login", handle_check_login)
    app.router.add_get("/debts", handle_debts)
    app.router.add_get("/anaf", handle_anaf)
    app.router.add_get("/taxes", handle_taxes)
    app.router.add_post("/logout", handle_logout)
    app.router.add_post("/scrape-all", handle_scrape_all)
    app.router.add_post("/restart-browser", handle_restart_browser)
    app.router.add_post("/eval", handle_eval)
    return app


if __name__ == "__main__":
    logging.basicConfig(
        format="%(asctime)s %(levelname)-8s %(message)s",
        level=LOG_LEVEL,
        datefmt="%Y-%m-%d %H:%M:%S",
        handlers=[logging.StreamHandler(sys.stdout)],
    )
    # Suppress noisy loggers
    logging.getLogger("nodriver.core.browser").setLevel(logging.WARNING)
    logging.getLogger("nodriver.core.tab").setLevel(logging.WARNING)
    logging.getLogger("nodriver.core.connection").setLevel(logging.WARNING)
    logging.getLogger("websockets.client").setLevel(logging.WARNING)

    logger.info("Starting ghiseul-browser service...")
    app = create_app()
    web.run_app(app, host=HOST, port=PORT)
