"""Shared fixtures and message-building helpers."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

SAMPLES = ROOT / "samples"


def build_eml(headers: dict[str, str], body: str = "", content_type: str = "text/plain") -> bytes:
    """Assemble a minimal but well-formed message with CRLF endings."""
    all_headers = {"Content-Type": f'{content_type}; charset="utf-8"', **headers}
    lines = [f"{k}: {v}" for k, v in all_headers.items()]
    text = "\n".join(lines) + "\n\n" + body
    return text.replace("\r\n", "\n").replace("\n", "\r\n").encode("utf-8")


@pytest.fixture(scope="session", autouse=True)
def _ensure_samples() -> None:
    """Generate the sample corpus if it is not already on disk."""
    if not list(SAMPLES.glob("*.eml")):
        import subprocess

        subprocess.run([sys.executable, str(SAMPLES / "generate.py")], check=True)


@pytest.fixture
def ctx():
    from phishtriage.analyzers import Context

    return Context(org_domains=("example-corp.com",))


@pytest.fixture
def analyze_raw():
    from phishtriage.analyzers import Context, analyze_bytes

    def _run(raw: bytes, **kwargs):
        return analyze_bytes(raw, "<test>", Context(**kwargs))

    return _run
