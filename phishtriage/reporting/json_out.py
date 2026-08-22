"""Machine-readable output.

Two shapes are produced:

``to_dict``  -- the full report, for piping into a SIEM, a case-management API
                or ``jq``. Stable key names; new keys may be added, existing
                ones will not change meaning.
``to_iocs``  -- observables only, in a flat list that maps cleanly onto a MISP
                attribute import or a threat-intel platform's bulk-add form.
"""

from __future__ import annotations

import json
from typing import Any

from ..models import Report
from ..utils import defang


def to_dict(report: Report, defanged: bool = True) -> dict[str, Any]:
    msg = report.email
    fang = defang.defang_url if defanged else (lambda s: s)
    fang_domain = defang.defang_domain if defanged else (lambda s: s)
    fang_email = defang.defang_email if defanged else (lambda s: s)
    fang_ip = defang.defang_ip if defanged else (lambda s: s)

    return {
        "schema": "phish-triage/report/1.0",
        "generated_at": report.generated_at.isoformat(),
        "source": msg.source_path,
        "online_checks": report.online_checks,
        "verdict": {
            "label": report.verdict.value,
            "score": report.score,
            "breakdown": report.breakdown,
        },
        "message": {
            "subject": defang.defang_text(msg.subject) if defanged else msg.subject,
            "from_display": msg.from_display,
            "from_address": fang_email(msg.from_address),
            "from_domain": fang_domain(msg.from_domain),
            "reply_to": fang_email(msg.reply_to),
            "return_path": fang_domain(msg.return_path),
            "to": [fang_email(a) for a in msg.to],
            "cc": [fang_email(a) for a in msg.cc],
            "date": msg.date_header,
            "message_id": msg.message_id,
            "size_bytes": msg.raw_size,
            "hop_count": len(msg.hops),
        },
        "hops": [
            {
                "index": h.index,
                "from_host": h.from_host,
                "from_ip": fang_ip(h.from_ip),
                "by_host": h.by_host,
                "protocol": h.with_proto,
                "timestamp": h.timestamp.isoformat() if h.timestamp else None,
                "delay_seconds": h.delay_seconds,
            }
            for h in msg.hops
        ],
        # Findings quote attacker infrastructure inside their evidence and detail
        # payloads, so the whole structure is defanged, not just the IOC list.
        "findings": [
            defang.defang_structure(f.as_dict()) if defanged else f.as_dict()
            for f in report.findings
        ],
        "attack_techniques": report.attack_techniques,
        "attachments": [a.as_dict() for a in msg.attachments],
        "urls": [
            {**u.as_dict(), "url": fang(u.url), "host": fang_domain(u.host),
             "registered_domain": fang_domain(u.registered_domain),
             "path": defang.defang_text(u.path) if defanged else u.path,
             "anchor_text": (defang.defang_text(u.anchor_text) if defanged
                             else u.anchor_text)}
            for u in msg.urls
        ],
        "iocs": to_iocs(report, defanged=defanged),
    }


def to_iocs(report: Report, defanged: bool = True) -> list[dict[str, str]]:
    """Flat observable list, one dict per IOC."""
    raw = report.iocs()
    out: list[dict[str, str]] = []

    def add(kind: str, value: str, transform) -> None:
        if value:
            out.append({"type": kind, "value": transform(value) if defanged else value})

    for url in raw["urls"]:
        add("url", url, defang.defang_url)
    for domain in raw["domains"]:
        add("domain", domain, defang.defang_domain)
    for domain in raw["sender_domain"]:
        add("sender-domain", domain, defang.defang_domain)
    for ip in raw["sender_ips"]:
        add("ip-src", ip, defang.defang_ip)
    for sha in raw["attachment_sha256"]:
        add("sha256", sha, lambda s: s)
    return out


def dumps(report: Report, defanged: bool = True, indent: int = 2) -> str:
    return json.dumps(to_dict(report, defanged=defanged), indent=indent, ensure_ascii=False)


def dumps_iocs(report: Report, defanged: bool = True) -> str:
    return json.dumps(to_iocs(report, defanged=defanged), indent=2, ensure_ascii=False)


def dumps_summary(reports: list[Report], defanged: bool = True) -> str:
    """Compact one-line-per-message form, for batch runs."""
    rows = [
        {
            "source": r.email.source_path,
            "verdict": r.verdict.value,
            "score": r.score,
            "subject": (defang.defang_text(r.email.subject[:120]) if defanged
                        else r.email.subject[:120]),
            "from": defang.defang_email(r.email.from_address) if defanged
                    else r.email.from_address,
            "top_indicators": [f.id for f in r.findings[:5]],
            "attack": r.attack_techniques,
        }
        for r in reports
    ]
    return json.dumps(rows, indent=2, ensure_ascii=False)
