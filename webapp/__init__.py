"""Flask front end for phish-triage.

Optional. The CLI has no dependency on this package, and this package adds no
detection logic of its own -- it is a thin, hardened input surface over the same
engine.

    pip install -e ".[web]"
    phish-triage-web
"""

from __future__ import annotations

from flask import Flask, jsonify, render_template, request

from phishtriage import __version__

from .config import Config
from .security import apply_security_headers, issue_csrf_token
from .store import RateLimiter, ResultStore
from .views import bp

__all__ = ["create_app", "Config"]


def create_app(config: Config | None = None, **overrides) -> Flask:
    cfg = config or Config()
    for key, value in overrides.items():
        if hasattr(cfg, key):
            setattr(cfg, key, value)

    app = Flask(__name__, static_folder="static", template_folder="templates")
    app.config.update(cfg.as_flask())

    app.extensions["phish_triage"] = {
        "config": cfg,
        "store": ResultStore(cfg.result_ttl_seconds, cfg.max_stored_results),
        "limiter": RateLimiter(cfg.rate_limit_requests, cfg.rate_limit_window_seconds),
    }

    app.register_blueprint(bp)
    app.after_request(apply_security_headers)
    _register_error_handlers(app)

    @app.context_processor
    def _globals():
        return {"app_version": __version__}

    return app


def _register_error_handlers(app: Flask) -> None:
    def render_error(code: int, message: str):
        if request.path.startswith("/api/"):
            return jsonify(error=message, status=code), code
        return render_template(
            "error.html", code=code, message=message,
            csrf_token=issue_csrf_token(), version=__version__,
        ), code

    @app.errorhandler(400)
    def _bad_request(error):
        return render_error(400, getattr(error, "description", "Bad request."))

    @app.errorhandler(403)
    def _forbidden(error):
        return render_error(403, getattr(error, "description", "Forbidden."))

    @app.errorhandler(404)
    def _not_found(error):
        return render_error(404, getattr(error, "description", "Not found."))

    @app.errorhandler(413)
    def _too_large(error):
        limit = app.config["MAX_CONTENT_LENGTH"] / (1024 * 1024)
        return render_error(413, f"That upload is larger than the {limit:.1f} MB limit.")

    @app.errorhandler(422)
    def _unprocessable(error):
        return render_error(422, getattr(error, "description", "Could not parse the message."))

    @app.errorhandler(429)
    def _rate_limited(error):
        return render_error(429, getattr(error, "description", "Too many requests."))

    @app.errorhandler(500)
    def _server_error(error):  # pragma: no cover - defensive
        # Never echo the exception: it can contain fragments of the message.
        return render_error(500, "Something went wrong while analysing that message.")
