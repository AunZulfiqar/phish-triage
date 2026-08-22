"""Development server entry point.

    phish-triage-web
    python -m webapp --port 8000

Binds to 127.0.0.1 by default. This application accepts hostile input and holds
analysed messages in memory; exposing it on 0.0.0.0 without a reverse proxy and
an authentication layer in front of it is not something to do by accident, so
the wider bind has to be asked for explicitly.

Flask's built-in server is for development. For anything shared, run it behind
a real WSGI server:

    waitress-serve --listen 127.0.0.1:8000 "webapp:create_app()"
    gunicorn -b 127.0.0.1:8000 "webapp:create_app()"
"""

from __future__ import annotations

import argparse
import os
import sys


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="phish-triage-web",
        description="Web front end for phish-triage.",
    )
    parser.add_argument("--host", default="127.0.0.1",
                        help="interface to bind (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=int(os.environ.get("PORT", 8000)))
    parser.add_argument("--debug", action="store_true",
                        help="enable the reloader and debugger (never use this on a shared host)")
    parser.add_argument("--allow-online", action="store_true",
                        help="permit live SPF/DMARC DNS lookups")
    parser.add_argument("--org-domain", action="append", default=[], metavar="DOMAIN",
                        help="a domain your organisation owns; repeatable")
    args = parser.parse_args(argv)

    from . import Config, create_app

    config = Config()
    if args.allow_online:
        config.allow_online_checks = True
    if args.org_domain:
        config.org_domains = tuple(d.lower() for d in args.org_domain)

    app = create_app(config)

    if args.host not in ("127.0.0.1", "localhost", "::1"):
        print(f"warning: binding to {args.host} exposes this service beyond localhost.\n"
              "         Put it behind a reverse proxy with authentication.",
              file=sys.stderr)

    print(f"phish-triage web UI  ->  http://{args.host}:{args.port}")
    print(f"  online checks : {'enabled' if config.allow_online_checks else 'disabled'}")
    print(f"  org domains   : {', '.join(config.org_domains) or '(none)'}")
    print(f"  result TTL    : {config.result_ttl_seconds}s, in memory only")
    app.run(host=args.host, port=args.port, debug=args.debug)
    return 0


if __name__ == "__main__":
    sys.exit(main())
