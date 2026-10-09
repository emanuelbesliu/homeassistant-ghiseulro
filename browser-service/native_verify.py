"""Locate an unchecked verification box on X11 and send real display input.

The caller must establish that Chromium is on a Cloudflare challenge before
calling this module. Screenshots stay in memory; no credentials leave the host.
"""

import os
import time
from functools import lru_cache

import cv2
import numpy as np
from mss import mss
from nodriver.core.util import get_cf_template


@lru_cache(maxsize=1)
def checkbox_templates():
    # nodriver's supplied reference centers the checkbox at (55, 36).
    # Exclude its English text: fonts and translations must not affect matching.
    source = cv2.imdecode(
        np.frombuffer(get_cf_template(), dtype=np.uint8), cv2.IMREAD_GRAYSCALE
    )
    template = source[13:60, 32:78]
    variants = []
    for scale in np.arange(0.8, 2.001, 0.05):
        scaled = cv2.resize(template, None, fx=float(scale), fy=float(scale))
        for pixels in (scaled, 255 - scaled):
            variants.append((pixels, float(scale)))
    return variants


def find_checkbox(gray, threshold=0.90):
    """Return one confident, unchecked box; abstain if absent or ambiguous."""
    candidates = []
    for template, scale in checkbox_templates():
        height, width = template.shape
        if height > gray.shape[0] or width > gray.shape[1]:
            continue
        scores = cv2.matchTemplate(gray, template, cv2.TM_CCOEFF_NORMED)
        # Inspect a second peak as well, so two boxes never become a blind guess.
        for _ in range(2):
            _, confidence, _, position = cv2.minMaxLoc(scores)
            if confidence < threshold:
                break
            x = round(position[0] + 23 * scale)
            y = round(position[1] + 23 * scale)
            radius = max(3, round(6 * scale))
            inside = gray[y - radius : y + radius, x - radius : x + radius]
            # A tick or spinner must not be clicked again as an empty checkbox.
            if inside.size and float(inside.std()) < 12:
                candidates.append((float(confidence), x, y, scale))
            px, py = position
            scores[
                max(0, py - height) : py + height,
                max(0, px - width) : px + width,
            ] = -1
    if not candidates:
        return None
    candidates.sort(reverse=True)
    confidence, x, y, scale = candidates[0]
    if any(
        abs(other_x - x) > 15 * max(scale, other_scale)
        or abs(other_y - y) > 15 * max(scale, other_scale)
        for _, other_x, other_y, other_scale in candidates[1:]
    ):
        return None
    return {"x": x, "y": y, "confidence": round(confidence, 4)}


def locate_on_display():
    """Read the actual Xvfb display, including cross-origin/closed-shadow UI."""
    with mss(display=os.environ.get("DISPLAY")) as capture:
        monitor = capture.monitors[0]
        pixels = np.asarray(capture.grab(monitor))
        match = find_checkbox(cv2.cvtColor(pixels, cv2.COLOR_BGRA2GRAY))
        if match:
            match["x"] += monitor["left"]
            match["y"] += monitor["top"]
        return match


def click_on_display(x, y):
    """Move and click through XTEST, not JavaScript or a CDP mouse event."""
    from Xlib import X, display
    from Xlib.ext import xtest

    connection = display.Display(os.environ.get("DISPLAY"))
    pressed = False
    try:
        screen = connection.screen()
        if not (0 <= x < screen.width_in_pixels and 0 <= y < screen.height_in_pixels):
            raise ValueError("Verification position is outside the virtual display")
        if not connection.has_extension("XTEST"):
            raise RuntimeError("Virtual display does not support XTEST mouse input")
        pointer = screen.root.query_pointer()
        for step in range(1, 9):
            xtest.fake_input(
                connection,
                X.MotionNotify,
                x=round(pointer.root_x + (x - pointer.root_x) * step / 8),
                y=round(pointer.root_y + (y - pointer.root_y) * step / 8),
            )
            connection.sync()
            time.sleep(0.015)
        xtest.fake_input(connection, X.ButtonPress, 1)
        pressed = True
        connection.sync()
        time.sleep(0.08)
    finally:
        try:
            if pressed:
                xtest.fake_input(connection, X.ButtonRelease, 1)
                connection.sync()
        finally:
            connection.close()
