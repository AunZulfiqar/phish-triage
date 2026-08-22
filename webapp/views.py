"""Routes.

The web UI is a front end for exactly the same engine the CLI drives -- there is
no second implementation of any check, and no analysis logic in this module.
Everything here is input handling, and the input is hostile.
"""

from __future__ import annotations

import json
from pathlib import PurePath
from types import SimpleNamespace

from flask import (
    Blueprint,
    Response,
    abort,
    current_app,
    jsonify,
    render_template,
    request,
    url_for,
)

from phishtriage import __version__, catalog
from phishtriage.analyzers import Context, analyze_bytes
from phishtriage.reporting import html_out, json_out
from phishtriage.scoring import explain
from phishtriage.utils import defang

from .security import csrf_protect, issue_csrf_token, rate_limited

bp = Blueprint("triage", __name__)

_ALLOWED_SUFFIXES = {".eml", ".txt", ".msg", ""}


def _services():
    return current_app.extensions["phish_triage"]


def _context(online_requested: bool) -> Context:
    cfg = _services()["config"]
    online = bool(online_requested) and cfg.allow_online_checks
    return Context(online=online, org_domains=cfg.org_domains)


def _safe_label(filename: str) -> str:
    """A display name for an uploaded file.

    The client controls this string entirely. It is never used to build a path,
    so the only requirement is that it cannot break out of the template or carry
    a directory component into a link.
    """
    name = PurePath(filename or "message.eml").name
    name = name.replace("\\", "/").split("/")[-1]
    cleaned = "".join(c for c in name if c.isprintable() and c not in '<>:"|?*')
    return (cleaned or "message.eml")[:120]


def _collect_uploads() -> list[tuple[str, bytes]]:
    cfg = _services()["config"]
    items: list[tuple[str, bytes]] = []

    for storage in request.files.getlist("messages"):
        if not storage or not storage.filename:
            continue
        suffix = PurePath(storage.filename).suffix.lower()
        if suffix not in _ALLOWED_SUFFIXES:
            abort(400, description=f"Unsupported file type '{suffix}'. Upload .eml files.")
        payload = storage.read()
        if payload:
            items.append((_safe_label(storage.filename), payload))

    pasted = (request.form.get("raw_message") or "").strip()
    if pasted:
        items.append(("pasted-message.eml", pasted.encode("utf-8", "replace")))

    if len(items) > cfg.max_files_per_request:
        abort(400, description=f"Too many files. The limit is {cfg.max_files_per_request}.")
    return items


def _ranked(reports: list) -> list[SimpleNamespace]:
    """Batch rows, worst first, keeping each report's original index for links."""
    pairs = [SimpleNamespace(index=i, report=r) for i, r in enumerate(reports)]
    pairs.sort(key=lambda p: (-p.report.score, p.report.email.source_path))
    return pairs


def _render_single(token: str, index: int, report_obj, batch_size: int = 0):
    return render_template(
        "report.html",
        token=token,
        index=index,
        report=report_obj,
        iocs=json_out.to_iocs(report_obj),
        defang=defang,
        rationale_line=explain(report_obj.score, report_obj.verdict, report_obj.breakdown),
        category_titles=catalog.CATEGORY_TITLES,
        batch_size=batch_size,
        csrf_token=issue_csrf_token(),
        version=__version__,
    )


def _analyze_all(items: list[tuple[str, bytes]], ctx: Context) -> list:
    reports = []
    for label, payload in items:
        try:
            reports.append(analyze_bytes(payload, label, ctx))
        except Exception:
            abort(422, description=f"'{label}' could not be parsed as an RFC 5322 message.")
    return reports


# --------------------------------------------------------------------- UI ---

@bp.get("/")
def index():
    cfg = _services()["config"]
    return render_template(
        "index.html",
        csrf_token=issue_csrf_token(),
        version=__version__,
        indicator_count=len(catalog.all_indicators()),
        category_count=len(catalog.CATEGORIES),
        max_upload_mb=round(cfg.max_content_length / (1024 * 1024), 1),
        max_files=cfg.max_files_per_request,
        online_available=cfg.allow_online_checks,
        org_domains=cfg.org_domains,
    )


@bp.post("/analyze")
@rate_limited
@csrf_protect
def analyze():
    items = _collect_uploads()
    if not items:
        abort(400, description="Nothing to analyse. Attach a .eml file or paste a message.")

    ctx = _context(request.form.get("online") == "on")
    reports = _analyze_all(items, ctx)
    token = _services()["store"].put(reports, online=ctx.online)
    return Response(status=303, headers={"Location": url_for("triage.report", token=token)})


@bp.get("/report/<token>")
def report(token: str):
    entry = _services()["store"].get(token)
    if entry is None:
        abort(404, description="That report has expired or does not exist. Results are held "
                               "in memory only and are not persisted.")
    if entry.is_batch:
        return render_template(
            "batch.html", token=token, reports=entry.reports,
            ranked=_ranked(entry.reports), defang=defang,
            csrf_token=issue_csrf_token(), version=__version__,
        )
    return _render_single(token, 0, entry.reports[0])


@bp.get("/report/<token>/message/<int:index>")
def report_item(token: str, index: int):
    entry = _services()["store"].get(token)
    if entry is None or not 0 <= index < len(entry.reports):
        abort(404, description="That report has expired or does not exist.")
    return _render_single(
        token, index, entry.reports[index],
        batch_size=len(entry.reports) if entry.is_batch else 0,
    )


@bp.post("/report/<token>/delete")
@csrf_protect
def delete_report(token: str):
    _services()["store"].discard(token)
    return Response(status=303, headers={"Location": url_for("triage.index")})


@bp.get("/indicators")
def indicators():
    grouped = {
        category: [i for i in catalog.all_indicators() if i.category == category]
        for category in catalog.CATEGORIES
    }
    return render_template("indicators.html", grouped=grouped, version=__version__,
                           total=len(catalog.all_indicators()))


# --------------------------------------------------------------- downloads ---

def _one_report(token: str, index: int):
    entry = _services()["store"].get(token)
    if entry is None or not 0 <= index < len(entry.reports):
        abort(404, description="That report has expired or does not exist.")
    return entry.reports[index]


@bp.get("/report/<token>/download/<int:index>.json")
def download_json(token: str, index: int):
    report_obj = _one_report(token, index)
    payload = json_out.dumps(report_obj, defanged=True)
    stem = PurePath(report_obj.email.source_path).stem or "report"
    return Response(
        payload,
        mimetype="application/json",
        headers={"Content-Disposition": f'attachment; filename="{stem}.triage.json"'},
    )


@bp.get("/report/<token>/download/<int:index>.html")
def download_html(token: str, index: int):
    report_obj = _one_report(token, index)
    stem = PurePath(report_obj.email.source_path).stem or "report"
    return Response(
        html_out.render(report_obj),
        mimetype="text/html",
        headers={"Content-Disposition": f'attachment; filename="{stem}.triage.html"'},
    )


@bp.get("/report/<token>/download/iocs.json")
def download_iocs(token: str):
    entry = _services()["store"].get(token)
    if entry is None:
        abort(404, description="That report has expired or does not exist.")
    merged: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for report_obj in entry.reports:
        for ioc in json_out.to_iocs(report_obj, defanged=True):
            key = (ioc["type"], ioc["value"])
            if key not in seen:
                seen.add(key)
                merged.append(ioc)
    return Response(
        json.dumps(merged, indent=2),
        mimetype="application/json",
        headers={"Content-Disposition": 'attachment; filename="iocs.json"'},
    )


# --------------------------------------------------------------------- API ---

@bp.post("/api/analyze")
@rate_limited
@csrf_protect
def api_analyze():
    """Analyse one message and return the full report as JSON.

    Accepts a multipart upload under ``message``/``messages``, or a JSON body
    of ``{"raw": "<rfc5322 text>"}``.
    """
    items: list[tuple[str, bytes]] = []

    if request.files:
        for field in ("message", "messages"):
            for storage in request.files.getlist(field):
                if storage and storage.filename:
                    items.append((_safe_label(storage.filename), storage.read()))
    elif request.is_json:
        body = request.get_json(silent=True) or {}
        raw = body.get("raw")
        if isinstance(raw, str) and raw.strip():
            items.append((_safe_label(body.get("filename", "message.eml")),
                          raw.encode("utf-8", "replace")))
    elif request.data:
        items.append(("message.eml", request.data))

    if not items:
        return jsonify(error="no message supplied"), 400

    cfg = _services()["config"]
    if len(items) > cfg.max_files_per_request:
        return jsonify(error=f"too many messages; limit is {cfg.max_files_per_request}"), 400

    online = str(request.args.get("online", "")).lower() in ("1", "true", "yes")
    ctx = _context(online)
    defanged = str(request.args.get("defang", "1")).lower() not in ("0", "false", "no")

    payloads = []
    for label, raw in items:
        try:
            payloads.append(json_out.to_dict(analyze_bytes(raw, label, ctx), defanged=defanged))
        except Exception:
            return jsonify(error=f"'{label}' could not be parsed"), 422

    return jsonify(payloads[0] if len(payloads) == 1 else {"reports": payloads})


@bp.get("/api/indicators")
def api_indicators():
    return jsonify([
        {
            "id": i.id, "name": i.name, "category": i.category,
            "severity": i.severity.value, "weight": i.weight,
            "description": i.description, "attack": list(i.attack),
        }
        for i in catalog.all_indicators()
    ])


@bp.get("/healthz")
def healthz():
    return jsonify(
        status="ok",
        version=__version__,
        indicators=len(catalog.all_indicators()),
        stored_results=len(_services()["store"]),
    )
