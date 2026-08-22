"""URL analysis.

The single strongest indicator in the whole tool lives here: **anchor-text and
href disagreement**. When a link reads ``https://www.paypal.com/verify`` but
points at ``https://paypal-secure.example.tk/``, there is no benign explanation.
Legitimate senders whose display text differs from the target (tracking links,
newsletter redirectors) almost always show non-URL text such as "Read more" --
so the check only fires when the anchor text *itself claims to be a domain*.

Nothing here resolves a URL. Fetching an attacker's link from the analyst's
machine confirms delivery, leaks the environment and can burn the investigation.
Shorteners are therefore flagged as unresolved rather than followed.
"""

from __future__ import annotations

import re
from urllib.parse import parse_qs, urlsplit

from ..intel import brands, tlds
from ..models import ExtractedURL, Finding, ParsedEmail
from ..utils import domains, homoglyph
from .base import Context, finding

_ANCHOR_DOMAIN_RE = re.compile(
    r"(?:https?://)?(?:www\.)?([A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
    r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+)",
)
_LOOKALIKE_MAX_DISTANCE = 2


class URLAnalyzer:
    name = "urls"
    category = "urls"

    def run(self, email: ParsedEmail, ctx: Context) -> list[Finding]:
        if not email.urls:
            return []
        findings: list[Finding] = []
        seen: set[str] = set()

        for url in email.urls:
            for check in (
                self._anchor_mismatch,
                self._dangerous_scheme,
                self._userinfo,
                self._bare_ip,
                self._punycode,
                self._mixed_script,
                self._lookalike,
                self._brand_subdomain,
                self._shortener,
                self._risky_tld,
                self._credential_path,
                self._open_redirect,
                self._plain_http,
            ):
                result = check(url, ctx)
                if result is None:
                    continue
                # One finding per indicator: the first, worst example is the
                # evidence. Repeats would inflate the score without adding
                # information for the analyst.
                if result.id in seen:
                    continue
                seen.add(result.id)
                findings.append(result)
        return findings

    # ------------------------------------------------------------- deception
    def _anchor_mismatch(self, url: ExtractedURL, ctx: Context) -> Finding | None:
        if url.source != "html-anchor" or not url.anchor_text or not url.registered_domain:
            return None
        match = _ANCHOR_DOMAIN_RE.search(url.anchor_text.strip())
        if not match:
            return None
        claimed_host = match.group(1).lower()
        # The anchor text has to actually look like a hostname, not "version 2.0".
        if not domains.split_host(claimed_host)[2]:
            return None
        claimed_rd = domains.registered_domain(claimed_host)
        if not claimed_rd or domains.same_org(claimed_rd, url.registered_domain):
            return None
        return finding(
            "URL-001",
            f'Link text shows "{claimed_host}" but the href resolves to {url.host}',
            anchor_text=url.anchor_text[:200], claimed_domain=claimed_rd,
            actual_domain=url.registered_domain, url=url.url,
        )

    def _dangerous_scheme(self, url: ExtractedURL, ctx: Context) -> Finding | None:
        if url.scheme not in ("data", "javascript", "vbscript"):
            return None
        return finding(
            "URL-012", f"{url.scheme}: URI present in the message body",
            scheme=url.scheme, snippet=url.url[:200],
        )

    def _userinfo(self, url: ExtractedURL, ctx: Context) -> Finding | None:
        try:
            authority = urlsplit(url.url).netloc
        except ValueError:
            return None
        if "@" not in authority:
            return None
        decoy, _, real = authority.rpartition("@")
        return finding(
            "URL-013",
            f'Everything before the @ ("{decoy[:80]}") is ignored; the browser connects to {real}',
            decoy=decoy[:120], real_host=real, url=url.url,
        )

    # -------------------------------------------------------------- hostname
    def _bare_ip(self, url: ExtractedURL, ctx: Context) -> Finding | None:
        if not domains.is_ip(url.host):
            return None
        return finding("URL-005", f"Link targets the IP address {url.host}",
                       ip=url.host, url=url.url)

    def _punycode(self, url: ExtractedURL, ctx: Context) -> Finding | None:
        if "xn--" not in url.host:
            return None
        rendered = homoglyph.decode_punycode(url.host)
        evidence = f"Host {url.host} is punycode"
        if rendered:
            evidence += f' and renders as "{rendered}"'
        return finding("URL-002", evidence, host=url.host, renders_as=rendered or "", url=url.url)

    def _mixed_script(self, url: ExtractedURL, ctx: Context) -> Finding | None:
        rendered = homoglyph.decode_punycode(url.host) or url.host
        if not homoglyph.is_mixed_script(rendered):
            return None
        confusables = homoglyph.confusable_chars(rendered)
        if not confusables:
            return None
        described = ", ".join(f"'{c}' ({name}, {script})" for c, name, script in confusables[:3])
        return finding(
            "URL-003",
            f"Host {rendered} mixes Unicode scripts: {described}",
            host=url.host, rendered=rendered,
            confusables=[{"char": c, "name": n, "script": s} for c, n, s in confusables],
        )

    def _lookalike(self, url: ExtractedURL, ctx: Context) -> Finding | None:
        rd = url.registered_domain
        if not rd or rd in brands.LEGITIMATE_DOMAINS:
            return None
        if any(domains.same_org(rd, d) for d in ctx.org_domains):
            return None
        label = domains.split_host(url.host)[1]
        best: tuple[int, str, str] | None = None
        for brand, canonical in brands.CANONICAL.items():
            brand_label = canonical.split(".")[0]
            distance = domains.levenshtein(label, brand_label, cap=_LOOKALIKE_MAX_DISTANCE)
            if distance == 0 or distance > _LOOKALIKE_MAX_DISTANCE:
                continue
            # Guard against short labels where distance 2 is meaningless.
            if len(brand_label) < 5:
                continue
            if best is None or distance < best[0]:
                best = (distance, brand, canonical)
        if best is None:
            return None
        distance, brand, canonical = best
        return finding(
            "URL-004",
            f"Registered domain {rd} is {distance} character(s) from {canonical}",
            registered_domain=rd, resembles=canonical, brand=brand,
            edit_distance=distance, url=url.url,
        )

    def _brand_subdomain(self, url: ExtractedURL, ctx: Context) -> Finding | None:
        subdomain = domains.subdomain_of(url.host)
        if not subdomain:
            return None
        rd = url.registered_domain
        if rd in brands.LEGITIMATE_DOMAINS or any(
            domains.same_org(rd, d) for d in ctx.org_domains
        ):
            return None
        lowered = subdomain.lower()
        for brand, legit in brands.BRANDS.items():
            if brand not in lowered:
                continue
            return finding(
                "URL-010",
                f'Subdomain "{subdomain}" advertises {brand} but the domain is {rd}',
                subdomain=subdomain, brand=brand, registered_domain=rd,
                legitimate_domains=list(legit), url=url.url,
            )
        if lowered.count(".") >= 3:
            return finding(
                "URL-010",
                f'Unusually deep subdomain chain: "{subdomain}.{rd}"',
                subdomain=subdomain, depth=lowered.count(".") + 1, registered_domain=rd,
            )
        return None

    # ------------------------------------------------------------ reputation
    def _shortener(self, url: ExtractedURL, ctx: Context) -> Finding | None:
        if url.registered_domain not in tlds.URL_SHORTENERS:
            return None
        return finding(
            "URL-006",
            f"{url.registered_domain} shortener hides the true destination of {url.url}",
            shortener=url.registered_domain, url=url.url,
            note="Not resolved: fetching the link would confirm delivery to the sender.",
        )

    def _risky_tld(self, url: ExtractedURL, ctx: Context) -> Finding | None:
        tld = domains.tld(url.host)
        if not tld or tld not in tlds.HIGH_ABUSE_TLDS:
            return None
        return finding("URL-007", f"Link uses the .{tld} TLD ({url.registered_domain})",
                       tld=tld, registered_domain=url.registered_domain)

    # ----------------------------------------------------------------- path
    def _credential_path(self, url: ExtractedURL, ctx: Context) -> Finding | None:
        if not url.path:
            return None
        if url.registered_domain in brands.LEGITIMATE_DOMAINS:
            return None
        if any(domains.same_org(url.registered_domain, d) for d in ctx.org_domains):
            return None
        tokens = {t for t in re.split(r"[^a-z0-9]+", url.path.lower()) if t}
        hits = sorted(tokens & tlds.CREDENTIAL_PATH_TERMS)
        if len(hits) < 2:
            return None
        return finding(
            "URL-008",
            f"Path on {url.registered_domain} contains {', '.join(hits[:5])}",
            registered_domain=url.registered_domain, terms=hits, path=url.path[:200],
        )

    def _open_redirect(self, url: ExtractedURL, ctx: Context) -> Finding | None:
        try:
            query = urlsplit(url.url).query
        except ValueError:
            return None
        if not query:
            return None
        for key, values in parse_qs(query).items():
            if key.lower() not in tlds.REDIRECT_PARAMS:
                continue
            for value in values:
                if re.match(r"(?i)^(https?%3a|https?:)//?", value or ""):
                    return finding(
                        "URL-009",
                        f"{url.registered_domain} carries a redirect parameter "
                        f"{key}={value[:100]}",
                        host=url.host, parameter=key, destination=value[:200],
                    )
        return None

    def _plain_http(self, url: ExtractedURL, ctx: Context) -> Finding | None:
        if url.scheme != "http" or domains.is_ip(url.host):
            return None
        tokens = {t for t in re.split(r"[^a-z0-9]+", url.path.lower()) if t}
        if not tokens & tlds.CREDENTIAL_PATH_TERMS:
            return None
        return finding("URL-011", f"Action link served over plain HTTP: {url.url[:160]}",
                       url=url.url)
