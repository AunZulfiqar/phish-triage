#!/usr/bin/env python3
"""Regenerate the README screenshots.

    python tools/screenshots.py

Self-contained and deterministic: it starts its own server on a free port,
seeds the result store in-process with the synthetic sample corpus (so the
report tokens are known without having to drive the upload form), drives
headless Chrome, and trims the trailing background from each capture.

Because it only ever analyses ``samples/``, the screenshots contain no real
mail -- which is the whole reason the corpus is generated rather than collected.

Chrome is located automatically; set CHROME to override.
"""

from __future__ import annotations

import os
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from phishtriage.analyzers import Context, analyze_bytes  # noqa: E402

OUT = ROOT / "docs" / "screenshots"
WIDTH = 1400

_CHROME_CANDIDATES = (
    os.environ.get("CHROME", ""),
    r"C:\Program Files\Google\Chrome\Application\chrome.exe",
    r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
    "google-chrome", "google-chrome-stable", "chromium", "chromium-browser",
)


def find_chrome() -> str:
    for candidate in _CHROME_CANDIDATES:
        if not candidate:
            continue
        if os.path.isfile(candidate):
            return candidate
        found = shutil.which(candidate)
        if found:
            return found
    raise SystemExit(
        "Chrome not found. Install Chrome or Chromium, or set CHROME=/path/to/chrome"
    )


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def start_server(port: int):
    """Serve the app in a background thread and seed it with known reports."""
    from webapp import Config, create_app

    app = create_app(Config(
        secret_key="screenshots-only",
        org_domains=("example-corp.com",),
        result_ttl_seconds=3600,
    ))

    ctx = Context(org_domains=("example-corp.com",))
    order = [
        "credential-phish.eml", "malware-attachment.eml", "bec-wire-fraud.eml",
        "benign-receipt.eml", "benign-newsletter.eml",
    ]
    # analyze_bytes with a bare filename, not analyze_file: the report shows its
    # own source path, and analyze_file would put this machine's absolute path
    # into a screenshot that gets committed to a public repository.
    reports = [
        analyze_bytes((ROOT / "samples" / name).read_bytes(), name, ctx)
        for name in order
    ]

    store = app.extensions["phish_triage"]["store"]
    tokens = {
        "single": store.put([reports[0]]),
        "batch": store.put(reports),
    }

    thread = threading.Thread(
        target=lambda: app.run(host="127.0.0.1", port=port, debug=False,
                               use_reloader=False, threaded=True),
        daemon=True,
    )
    thread.start()

    base = f"http://127.0.0.1:{port}"
    for _ in range(100):
        try:
            import urllib.request
            urllib.request.urlopen(f"{base}/healthz", timeout=1).read()
            break
        except Exception:
            time.sleep(0.1)
    else:
        raise SystemExit("the screenshot server never came up")
    return base, tokens


def capture(chrome: str, url: str, target: Path, height: int) -> None:
    target.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory() as profile:
        subprocess.run(
            [
                chrome, "--headless", "--disable-gpu", "--hide-scrollbars",
                "--force-dark-mode", "--no-first-run", "--no-default-browser-check",
                f"--user-data-dir={profile}",
                "--virtual-time-budget=5000",
                f"--window-size={WIDTH},{height}",
                f"--screenshot={target}",
                url,
            ],
            check=True, capture_output=True,
        )


def trim(path: Path, keep_padding: int = 28) -> tuple[int, int]:
    """Crop the trailing page background so captures are not mostly empty.

    The window has to be taller than the content to avoid cutting it off, which
    leaves a band of flat background at the bottom. Rows identical to the
    bottom-left pixel are removed, minus a little breathing room.
    """
    from PIL import Image

    with Image.open(path) as image:
        rgb = image.convert("RGB")
        width, height = rgb.size
        background = rgb.getpixel((2, height - 2))

        last_content = 0
        for y in range(height - 1, -1, -1):
            row = rgb.crop((0, y, width, y + 1)).getcolors(maxcolors=width * 2)
            if not (len(row) == 1 and row[0][1] == background):
                last_content = y
                break

        bottom = min(height, last_content + keep_padding)
        cropped = rgb.crop((0, 0, width, bottom))
        cropped.save(path, "PNG", optimize=True)
        return cropped.size


SHOTS = (
    # (filename, path template, window height, caption)
    ("01-analyse.png", "/", 980, "Upload / paste form"),
    ("02-report.png", "/report/{single}", 1190, "Verdict, identities and authentication"),
    ("03-indicators.png", "/report/{single}/message/0#indicators", 3400,
     "Full report with every indicator that fired"),
    ("04-batch.png", "/report/{batch}", 1150, "Batch triage, ranked worst first"),
    ("05-catalogue.png", "/indicators", 1250, "The published indicator catalogue"),
)


def main() -> None:
    chrome = find_chrome()
    port = free_port()
    base, tokens = start_server(port)
    print(f"chrome : {chrome}")
    print(f"server : {base}\n")

    for name, template, height, caption in SHOTS:
        target = OUT / name
        capture(chrome, base + template.format(**tokens), target, height)
        width, cropped_height = trim(target)
        size_kb = target.stat().st_size / 1024
        print(f"  {name:20} {width}x{cropped_height:<5} {size_kb:6.0f} KB  {caption}")

    print(f"\nwrote {len(SHOTS)} screenshots to {OUT.relative_to(ROOT)}/")


if __name__ == "__main__":
    main()
