"""
ghiseul-browser: A lightweight browser microservice for ghiseul.ro.

Uses nodriver (stealthy Chrome automation) with a persistent browser instance
to handle verification and scrape debt/tax data. A browser console supports
manual verification when automatic challenge handling cannot complete.

All requests share the same browser in a single asyncio event loop,
keeping cookies and session state alive between calls.
"""

import asyncio
import json
import logging
import math
import os
import re
import sys
import time
from typing import Optional
from urllib.parse import urlsplit

import nodriver as nd
from aiohttp import web

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
HOST = os.environ.get("HOST", "0.0.0.0")
PORT = int(os.environ.get("PORT", 8192))
LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO").upper()
HEADLESS = os.environ.get("HEADLESS", "true").lower() == "true"
SERVICE_VERSION = "2.0.2-auto.1"
USER_DATA_DIR = os.environ.get("USER_DATA_DIR", "/data/chrome")
ENABLE_VNC = os.environ.get("ENABLE_VNC", "false").lower() == "true"
CF_NATIVE_CLICK = os.environ.get("CF_NATIVE_CLICK", "true").lower() == "true"
CF_SOLVE_TIMEOUT = min(180, max(10, float(os.environ.get("CF_SOLVE_TIMEOUT", "90"))))
CF_RETRY_COOLDOWN = max(30, float(os.environ.get("CF_RETRY_COOLDOWN", "300")))

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

CF_CHALLENGE_TITLES = ["Just a moment...", "Just a moment…", "DDoS-Guard"]
CF_CHALLENGE_SELECTORS = [
    "#cf-challenge-running",
    "#cf-please-wait",
    "#challenge-form",
    "#challenge-spinner",
    "#trk_jschal_js",
    "#turnstile-wrapper",
    'iframe[src*="challenges.cloudflare.com"]',
]
ACCESS_DENIED_TITLES = ["Access denied", "Attention Required! | Cloudflare"]

logger = logging.getLogger("ghiseul-browser")

# ---------------------------------------------------------------------------
# Global browser state
# ---------------------------------------------------------------------------
browser: Optional[nd.Browser] = None
browser_lock = asyncio.Lock()
operation_lock = asyncio.Lock()
active_tab: Optional[nd.Tab] = None
challenge_pending = False
challenge_retry_at = 0.0
xvfb_display = None
vnc_processes = []
verification_attempt = {"outcome": "not_started", "clicks": 0, "last_method": None}


class CloudflareChallengeError(Exception):
    """Verification could not complete; this is not a credential failure."""

    def __init__(self, message, code="cloudflare_challenge", retry_after=300):
        super().__init__(message)
        self.code = code
        self.retry_after = retry_after


def start_xvfb():
    """Start virtual X display for head-full Chrome in headless environments."""
    global xvfb_display
    if xvfb_display is None and os.name != "nt" and not os.environ.get("DISPLAY"):
        from xvfbwrapper import Xvfb

        xvfb_display = Xvfb(width=1280, height=900, colordepth=24)
        xvfb_display.start()
        logger.info("Virtual display started")


async def start_vnc():
    """Offer a password-protected view of this browser, on the same display/IP."""
    if not ENABLE_VNC or vnc_processes:
        return
    password = os.environ.get("VNC_PASSWORD", "")
    if len(password) != 8 or not password.isascii():
        raise RuntimeError(
            "ENABLE_VNC requires VNC_PASSWORD to contain exactly 8 ASCII characters"
        )
    auth_path = "/tmp/ghiseul-vnc-password"
    proc = await asyncio.create_subprocess_exec(
        "x11vnc",
        "-storepasswd",
        password,
        auth_path,
        stdout=asyncio.subprocess.DEVNULL,
        stderr=asyncio.subprocess.DEVNULL,
    )
    if await proc.wait() != 0:
        raise RuntimeError("Could not configure VNC password")
    os.chmod(auth_path, 0o600)
    for command in [
        [
            "x11vnc",
            "-display",
            os.environ["DISPLAY"],
            "-forever",
            "-shared",
            "-rfbauth",
            auth_path,
            "-rfbport",
            "5900",
            "-listen",
            "127.0.0.1",
            "-quiet",
        ],
        ["websockify", "--web=/usr/share/novnc", "6080", "127.0.0.1:5900"],
    ]:
        vnc_processes.append(
            await asyncio.create_subprocess_exec(
                *command,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL,
            )
        )
    logger.info("Manual browser console enabled on port 6080")


async def get_browser() -> nd.Browser:
    """Get or create the persistent browser instance."""
    global browser, active_tab, challenge_pending, challenge_retry_at
    async with browser_lock:
        if browser is not None:
            # Check if browser process is still alive
            try:
                proc = getattr(browser, "_process", None) or getattr(
                    browser, "get_process", None
                )
                if proc is not None:
                    returncode = getattr(proc, "returncode", None)
                    if returncode is None:
                        # Process still running
                        return browser
                    logger.warning(
                        "Browser process died (rc=%s), recreating...", returncode
                    )
                else:
                    # No process attribute found; check if we have open tabs
                    if browser.tabs:
                        return browser
                    logger.warning("Browser has no tabs, recreating...")
            except Exception as e:
                logger.warning("Browser health check failed: %s, recreating...", e)
            # Stop the dead/stale instance so its Chrome subprocesses are torn
            # down (and reaped by tini) instead of leaking as zombies.
            try:
                browser.stop()
            except Exception:
                pass
            browser = None
            active_tab = None
            challenge_pending = False
            challenge_retry_at = 0.0

        logger.info("Creating new browser instance...")
        if HEADLESS:
            start_xvfb()
        await start_vnc()
        os.makedirs(USER_DATA_DIR, mode=0o700, exist_ok=True)
        # HEADLESS retains its old meaning: run a visible Chromium under Xvfb.
        # A real profile and ordinary browser defaults also support manual checks.
        options = nd.Config(
            headless=False,
            sandbox=False,
            user_data_dir=USER_DATA_DIR,
            lang=os.environ.get("BROWSER_LANGUAGE", "en-US"),
        )
        options.add_argument("--window-size=1280,900")
        browser = await nd.Browser.create(config=options)
        logger.info("Browser created successfully")
        return browser


async def stop_browser_instance(instance):
    """Allow Chromium to flush its persistent profile and release its lock."""
    process = getattr(instance, "_process", None)
    try:
        await asyncio.wait_for(
            instance.connection.send(nd.cdp.browser.close()), timeout=2
        )
    except Exception:
        pass
    try:
        instance.stop()
    except Exception:
        pass
    if process is not None:
        try:
            await asyncio.wait_for(process.wait(), timeout=5)
        except TimeoutError:
            process.kill()
            await process.wait()


def _walk_nodes(node):
    """Include shadow roots and nested frame documents in checkbox discovery."""
    yield node
    for field in ("children", "shadow_roots"):
        for child in getattr(node, field, None) or []:
            yield from _walk_nodes(child)
    child_document = getattr(node, "content_document", None)
    if child_document is not None:
        yield from _walk_nodes(child_document)


async def click_cf_verify_native(tab: nd.Tab) -> bool:
    """Recognize a visible checkbox and use X11 input on the same browser."""
    if not CF_NATIVE_CLICK or not os.environ.get("DISPLAY"):
        return False
    try:
        from native_verify import click_on_display, locate_on_display

        state = await read_page_state(tab)
        if (
            not is_challenge(state)
            or urlsplit(state.get("url", "")).hostname != "www.ghiseul.ro"
        ):
            return False
        await tab.activate()
        await asyncio.sleep(0.15)
        match = await asyncio.to_thread(locate_on_display)
        if not match:
            return False
        # The page may have finished verification while the image was analyzed.
        state = await read_page_state(tab)
        if (
            not is_challenge(state)
            or urlsplit(state.get("url", "")).hostname != "www.ghiseul.ro"
        ):
            return False
        await asyncio.to_thread(click_on_display, match["x"], match["y"])
        verification_attempt["last_method"] = "native_x11"
        verification_attempt["native_match_score"] = match["confidence"]
        logger.info(
            "Unattended verification: native X11 checkbox click (match %.3f)",
            match["confidence"],
        )
        return True
    except Exception as err:
        # Surface a missing display/dependency once instead of silently waiting.
        if "native_error" not in verification_attempt:
            verification_attempt["native_error"] = str(err)
            logger.warning("Native verification unavailable: %s", err)
        return False


async def click_cf_verify(tab: nd.Tab) -> bool:
    """Try native display input, then an accessible Cloudflare frame."""
    if await click_cf_verify_native(tab):
        return True
    try:
        await tab.browser.update_targets()
        for target in tab.browser.targets:
            if urlsplit(target.url or "").hostname != "challenges.cloudflare.com":
                continue
            try:
                doc = await target.send(nd.cdp.dom.get_document(depth=-1, pierce=True))
            except Exception as err:
                logger.debug("Cloudflare target has no accessible document: %s", err)
                continue
            for node in _walk_nodes(doc):
                attrs = getattr(node, "attributes", None) or []
                attrs = dict(zip(attrs[::2], attrs[1::2]))
                if (
                    node.node_name.upper() == "INPUT"
                    and attrs.get("type", "").lower() == "checkbox"
                    and "checked" not in attrs
                    and "disabled" not in attrs
                ):
                    await nd.Element(node, target, doc).mouse_click()
                    verification_attempt["last_method"] = "cdp_frame"
                    logger.info(
                        "Unattended verification: Cloudflare frame checkbox click"
                    )
                    return True
    except Exception as e:
        logger.debug("Cloudflare checkbox is not accessible: %s", e)
    return False


async def read_page_state(tab: nd.Tab) -> dict:
    """Read live DOM state; target.title can lag behind a redirect."""
    result = await tab.evaluate(
        """
        JSON.stringify({
            title: document.title, url: location.origin + location.pathname,
            ready: document.readyState,
            marker: !!document.querySelector(PLACEHOLDER_SELECTORS),
            user_agent: navigator.userAgent,
            ray_id: (document.querySelector('.ray-id, #ray-id')?.textContent || '').trim()
        })
    """.replace(
            "PLACEHOLDER_SELECTORS", json.dumps(",".join(CF_CHALLENGE_SELECTORS))
        )
    )
    return json.loads(_safe_evaluate_result(result))


def is_challenge(state: dict) -> bool:
    title = state.get("title", "").strip().lower()
    return title in [t.lower() for t in CF_CHALLENGE_TITLES] or bool(
        state.get("marker")
    )


def is_blocked(state: dict) -> bool:
    title = state.get("title", "").strip().lower()
    return any(title.startswith(t.lower()) for t in ACCESS_DENIED_TITLES)


async def solve_cf_challenge(tab: nd.Tab, timeout: float = CF_SOLVE_TIMEOUT):
    """Attempt unattended verification within a deadline, with bounded input."""
    global challenge_pending, challenge_retry_at, verification_attempt
    started = time.monotonic()
    next_click_at = started + 3
    state = {}
    verification_attempt = {"outcome": "waiting", "clicks": 0, "last_method": None}
    try:
        async with asyncio.timeout(timeout):
            while True:
                try:
                    state = await asyncio.wait_for(read_page_state(tab), timeout=5)
                except Exception as err:
                    logger.debug("Page is navigating or unavailable: %s", err)
                    await asyncio.sleep(1)
                    continue
                if is_blocked(state):
                    challenge_pending = True
                    challenge_retry_at = time.monotonic() + CF_RETRY_COOLDOWN
                    verification_attempt["outcome"] = "blocked"
                    raise CloudflareChallengeError(
                        "Cloudflare denied access. See /diagnostics for the page state and Ray ID.",
                        code="cloudflare_blocked",
                        retry_after=math.ceil(CF_RETRY_COOLDOWN),
                    )
                if (
                    not is_challenge(state)
                    and state.get("ready") != "loading"
                    and urlsplit(state.get("url", "")).hostname == "www.ghiseul.ro"
                    and "ghiseul.ro" in state.get("title", "").lower()
                ):
                    challenge_pending = False
                    challenge_retry_at = 0.0
                    verification_attempt["outcome"] = "verified"
                    verification_attempt["elapsed_seconds"] = round(
                        time.monotonic() - started, 1
                    )
                    logger.info(
                        "Ghiseul.ro page ready after %.1fs", time.monotonic() - started
                    )
                    return
                if is_challenge(state) and not challenge_pending:
                    challenge_pending = True
                    logger.info("Cloudflare challenge detected: %s", state.get("title"))
                if (
                    is_challenge(state)
                    and time.monotonic() >= next_click_at
                    and verification_attempt["clicks"] < 3
                ):
                    try:
                        if await asyncio.wait_for(click_cf_verify(tab), timeout=8):
                            verification_attempt["clicks"] += 1
                    except TimeoutError:
                        logger.debug(
                            "Checkbox discovery timed out; still waiting for verification"
                        )
                    next_click_at = time.monotonic() + 10
                await asyncio.sleep(1)
    except TimeoutError:
        challenge_pending = True
        challenge_retry_at = time.monotonic() + CF_RETRY_COOLDOWN
        verification_attempt["outcome"] = "timeout"
        verification_attempt["elapsed_seconds"] = round(time.monotonic() - started, 1)
        logger.warning("Cloudflare/page timeout: %s", json.dumps(state))
        raise CloudflareChallengeError(
            f"Unattended Cloudflare verification did not finish within {timeout:g}s. "
            f"The next request after {math.ceil(CF_RETRY_COOLDOWN)}s can retry automatically. "
            "See /diagnostics for click attempts and page state.",
            retry_after=math.ceil(CF_RETRY_COOLDOWN),
        ) from None


async def navigate_and_solve(url: str) -> nd.Tab:
    """Reuse the profile/tab and retry expired challenges after the cooldown."""
    global active_tab, challenge_pending, challenge_retry_at
    drv = await get_browser()
    if active_tab is not None and not active_tab.closed and challenge_pending:
        state = await asyncio.wait_for(read_page_state(active_tab), timeout=5)
        # A successful manual check can resume immediately, even during cooldown.
        if not is_challenge(state) and not is_blocked(state):
            challenge_pending = False
            challenge_retry_at = 0.0
        elif time.monotonic() < challenge_retry_at:
            remaining = math.ceil(challenge_retry_at - time.monotonic())
            raise CloudflareChallengeError(
                f"Cloudflare verification is pending. Next unattended attempt in {remaining}s.",
                retry_after=remaining,
            )
        elif challenge_retry_at:
            # A failed widget can expire. Refresh once per cooldown, preserving
            # the same browser/profile, instead of clicking a stale widget forever.
            challenge_retry_at = 0.0
            logger.info("Retrying expired verification page after cooldown")
            await asyncio.wait_for(active_tab.reload(), timeout=15)
    else:
        active_tab = await asyncio.wait_for(drv.get(url), timeout=30)
    await solve_cf_challenge(active_tab)
    return active_tab


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
    return (
        """
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
    """.replace(
            "PLACEHOLDER_PWD", json.dumps(password)
        )
        .replace("PLACEHOLDER_URL", json.dumps(LOGIN_URL))
        .replace("PLACEHOLDER_USER", json.dumps(username))
    )


# ---------------------------------------------------------------------------
# API Handlers
# ---------------------------------------------------------------------------


async def handle_health(request: web.Request) -> web.Response:
    """Health check endpoint."""
    return web.json_response(
        {
            "status": "ok",
            "version": SERVICE_VERSION,
            "browser_started": browser is not None,
            "verification_pending": challenge_pending,
            "console_enabled": ENABLE_VNC,
            "native_click_enabled": CF_NATIVE_CLICK,
        }
    )


async def handle_diagnostics(request: web.Request) -> web.Response:
    """Report browser/challenge state without returning credentials or cookies."""
    state = {}
    if active_tab is not None and not active_tab.closed:
        try:
            state = await asyncio.wait_for(read_page_state(active_tab), timeout=5)
        except Exception as err:
            state = {"error": str(err)}
    return web.json_response(
        {
            "status": "ok",
            "version": SERVICE_VERSION,
            "page": state,
            "verification_pending": challenge_pending,
            "retry_after": max(0, math.ceil(challenge_retry_at - time.monotonic())),
            "console_enabled": ENABLE_VNC,
            "console_running": bool(vnc_processes)
            and all(p.returncode is None for p in vnc_processes),
            "verification_attempt": verification_attempt,
        }
    )


async def handle_open_browser(request: web.Request) -> web.Response:
    """Open the Ghiseul.ro page for manual verification without submitting a login."""
    global active_tab, challenge_pending
    drv = await get_browser()
    if active_tab is None or active_tab.closed:
        active_tab = await asyncio.wait_for(drv.get(f"{BASE_URL}/"), timeout=30)
    await active_tab.activate()
    challenge_pending = True
    return web.json_response(
        {"status": "ok", "message": "Browser open; complete verification on port 6080"}
    )


async def handle_verify(request: web.Request) -> web.Response:
    """Test unattended page verification without submitting account credentials."""
    tab = await navigate_and_solve(f"{BASE_URL}/")
    return web.json_response(
        {
            "status": "ok",
            "verified": True,
            "version": SERVICE_VERSION,
            "page": await read_page_state(tab),
            "verification_attempt": verification_attempt,
        }
    )


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
        logger.info(
            f"Login response: {login_response[:100] if login_response else 'empty'}"
        )

        # Check if logged in
        is_logged = await ajax_post(tab, ESTE_LOGAT_URL, {})
        logged_in = is_logged.strip() == "1"
        logger.info(f"Logged in: {logged_in}")

        return web.json_response(
            {
                "status": "ok",
                "logged_in": logged_in,
                "login_response": login_response,
            }
        )
    except Exception as e:
        if isinstance(e, CloudflareChallengeError):
            raise
        logger.error(f"Login error: {e}", exc_info=True)
        return web.json_response({"status": "error", "message": str(e)}, status=500)


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
            return web.json_response(
                {"status": "ok", "logged_in": False, "message": "No active tab"}
            )

        is_logged = await ajax_post(tab, ESTE_LOGAT_URL, {})
        logged_in = is_logged.strip() == "1"
        return web.json_response({"status": "ok", "logged_in": logged_in})
    except Exception as e:
        logger.error(f"Check login error: {e}", exc_info=True)
        return web.json_response({"status": "error", "message": str(e)}, status=500)


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
            details_html = await ajax_get(tab, f"{INSTITUTION_DETAILS_URL}/{inst_id}")

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

            institutions.append(
                {
                    "id": inst_id,
                    "name": name,
                    "total": total,
                    "details_html": details_html,
                }
            )

        return web.json_response(
            {
                "status": "ok",
                "institutions": institutions,
                "institutions_html": institutions_html,
            }
        )
    except Exception as e:
        logger.error(f"Debts error: {e}", exc_info=True)
        return web.json_response({"status": "error", "message": str(e)}, status=500)


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

        return web.json_response(
            {
                "status": "ok",
                "anaf_page_html": anaf_page_html,
                "anaf_debts_html": anaf_debts_html,
            }
        )
    except Exception as e:
        logger.error(f"ANAF error: {e}", exc_info=True)
        return web.json_response({"status": "error", "message": str(e)}, status=500)


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

        return web.json_response(
            {
                "status": "ok",
                "taxes_html": taxes_html,
            }
        )
    except Exception as e:
        logger.error(f"Taxes error: {e}", exc_info=True)
        return web.json_response({"status": "error", "message": str(e)}, status=500)


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
        return web.json_response({"status": "error", "message": str(e)}, status=500)


async def handle_scrape_all(request: web.Request) -> web.Response:
    """
    POST /scrape-all
    Body: {"username": "...", "password": "..."}

    All-in-one endpoint: login + fetch debts + ANAF + taxes.
    This is the primary endpoint for the HA integration.
    Returns all data in a single response.
    """
    tab: Optional[nd.Tab] = None
    authenticated = False
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
        logger.info(
            f"Login response: {login_response[:100] if login_response else 'empty'}"
        )

        # Check login
        is_logged = await ajax_post(tab, ESTE_LOGAT_URL, {})
        if is_logged.strip() != "1":
            return web.json_response(
                {
                    "status": "error",
                    "message": "Login failed",
                    "login_response": login_response,
                },
                status=401,
            )
        authenticated = True

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

                institutions.append(
                    {
                        "id": inst_id,
                        "name": name,
                        "total": total,
                        "details_html": details_html,
                    }
                )

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
            authenticated = False
        except Exception:
            pass

        # Keep one tab open: closing Chromium's last tab terminates the browser
        # and loses the live verification session. The next scrape reuses it.
        logger.info("=== Full scrape complete ===")
        return web.json_response(
            {
                "status": "ok",
                "logged_in": True,
                "institutions": institutions,
                "institutions_html": institutions_html,
                "anaf_page_html": anaf_page_html,
                "anaf_debts_html": anaf_debts_html,
                "taxes_html": taxes_html,
            }
        )

    except Exception as e:
        if isinstance(e, CloudflareChallengeError):
            raise
        logger.error(f"Scrape-all error: {e}", exc_info=True)
        return web.json_response({"status": "error", "message": str(e)}, status=500)
    finally:
        if authenticated and tab is not None:
            try:
                await asyncio.wait_for(ajax_get(tab, LOGOUT_URL), timeout=5)
            except Exception:
                logger.debug("Could not log out after an interrupted scrape")


async def handle_restart_browser(request: web.Request) -> web.Response:
    """
    POST /restart-browser
    Force-restart the browser instance (useful if it gets stuck).
    """
    global browser, active_tab, challenge_pending, challenge_retry_at
    async with browser_lock:
        if browser is not None:
            await stop_browser_instance(browser)
            browser = None
        active_tab = None
        challenge_pending = False
        challenge_retry_at = 0.0
    return web.json_response({"status": "ok", "message": "Browser restarted"})


async def handle_eval(request: web.Request) -> web.Response:
    """POST /eval - Evaluate JS on the current page (debug only)."""
    try:
        body = await request.json()
        js_code = body.get("js", "")
        drv = await get_browser()
        tab = drv.main_tab
        if tab is None:
            return web.json_response(
                {"status": "error", "message": "No active tab"}, status=400
            )
        result = await tab.evaluate(js_code, await_promise=True)
        return web.json_response(
            {"status": "ok", "result": str(result) if result else None}
        )
    except Exception as e:
        return web.json_response({"status": "error", "message": str(e)}, status=500)


# ---------------------------------------------------------------------------
# Application setup
# ---------------------------------------------------------------------------


@web.middleware
async def serialize_browser_requests(request, handler):
    """Prevent logins, logouts, and browser restarts from racing each other."""
    if request.path == "/health":
        return await handler(request)
    if operation_lock.locked():
        return web.json_response(
            {
                "status": "error",
                "code": "browser_busy",
                "message": "Browser is busy",
                "retry_after": 5,
            },
            status=503,
            headers={"Retry-After": "5"},
        )
    async with operation_lock:
        try:
            return await handler(request)
        except CloudflareChallengeError as err:
            return web.json_response(
                {
                    "status": "error",
                    "code": err.code,
                    "message": str(err),
                    "retry_after": err.retry_after,
                },
                status=503,
                headers={"Retry-After": str(err.retry_after)},
            )


async def cleanup_browser(app):
    """Flush the profile and stop the optional display/console on shutdown."""
    global browser, active_tab, xvfb_display
    if browser is not None:
        await stop_browser_instance(browser)
        browser = None
        active_tab = None
    for proc in vnc_processes:
        if proc.returncode is None:
            proc.terminate()
            try:
                await asyncio.wait_for(proc.wait(), timeout=5)
            except TimeoutError:
                proc.kill()
                await proc.wait()
    vnc_processes.clear()
    if xvfb_display is not None:
        xvfb_display.stop()
        xvfb_display = None


def create_app() -> web.Application:
    app = web.Application(middlewares=[serialize_browser_requests])
    app.on_cleanup.append(cleanup_browser)
    app.router.add_get("/health", handle_health)
    app.router.add_get("/diagnostics", handle_diagnostics)
    app.router.add_post("/open-browser", handle_open_browser)
    app.router.add_post("/verify", handle_verify)
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
