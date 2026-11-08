#!/usr/bin/env bash
# Fix headless browser automation (browser_control / gowitness / XSS
# execution-confirmation / screenshots) on Debian/Kali.
#
# Root cause: the distro package `python3-playwright` is a Debian repack
# (version shows as "x.y.z+ds"). Its Python bindings (a) raise
# `KeyError: 'deviceDescriptors'` on startup and (b) can't drive the bundled
# Chromium — so every browser-backed tool silently fails. The official PyPI
# wheel ships a matching Node driver and works. We install it to the user site
# (shadows the distro package, fully reversible with `pip uninstall`), then
# fetch the matching Chromium build. browser_control already launches with
# --no-sandbox, which is required in containers/sandboxed shells.
set -e

echo "[*] Current playwright:"
python3 -c "import playwright,os;print('   ',playwright.__file__)" 2>/dev/null || echo "    (not importable)"

echo "[*] Installing the official PyPI playwright wheel to the user site..."
pip install --user --break-system-packages --force-reinstall --no-deps \
    --index-url https://pypi.org/simple/ "playwright==1.55.0"

echo "[*] Downloading the matching Chromium build..."
python3 -m playwright install chromium

echo "[*] Verifying..."
python3 - <<'PY'
from playwright.sync_api import sync_playwright
with sync_playwright() as p:
    b = p.chromium.launch(headless=True,
                          args=["--no-sandbox","--disable-dev-shm-usage","--disable-gpu"])
    pg = b.new_page(); pg.goto("about:blank")
    assert pg.evaluate("6*7") == 42
    b.close()
print("[✓] Browser automation works — browser_control/gowitness/XSS exec-confirm are usable.")
PY
