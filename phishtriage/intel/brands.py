"""Brand reference data for impersonation and lookalike detection.

This is deliberately a small, hand-curated list rather than a scraped top-1M
feed. Lookalike detection compares against *brands worth impersonating*; adding
thousands of low-profile domains only inflates the false-positive rate.

Extend ``BRANDS`` with your own organisation's domains before deploying this in
a real environment -- most phishing an organisation actually receives imitates
that organisation.
"""

from __future__ import annotations

# brand keyword -> the domains that legitimately belong to it
BRANDS: dict[str, tuple[str, ...]] = {
    "microsoft": ("microsoft.com", "microsoftonline.com", "office.com", "office365.com",
                  "live.com", "outlook.com", "sharepoint.com", "azure.com"),
    "google": ("google.com", "gmail.com", "googlemail.com", "youtube.com"),
    "apple": ("apple.com", "icloud.com"),
    "amazon": ("amazon.com", "amazonaws.com", "amazon.co.uk"),
    "paypal": ("paypal.com", "paypal.me"),
    "netflix": ("netflix.com",),
    "facebook": ("facebook.com", "fb.com", "meta.com"),
    "instagram": ("instagram.com",),
    "whatsapp": ("whatsapp.com",),
    "linkedin": ("linkedin.com",),
    "dropbox": ("dropbox.com", "dropboxusercontent.com"),
    "adobe": ("adobe.com", "adobelogin.com"),
    "docusign": ("docusign.com", "docusign.net"),
    "dhl": ("dhl.com", "dhl.de"),
    "fedex": ("fedex.com",),
    "ups": ("ups.com",),
    "chase": ("chase.com",),
    "wellsfargo": ("wellsfargo.com",),
    "hsbc": ("hsbc.com", "hsbc.co.uk"),
    "barclays": ("barclays.co.uk", "barclays.com"),
    "citibank": ("citi.com", "citibank.com"),
    "santander": ("santander.com", "santander.co.uk"),
    "coinbase": ("coinbase.com",),
    "binance": ("binance.com",),
    "steam": ("steampowered.com", "steamcommunity.com"),
    "zoom": ("zoom.us",),
    "slack": ("slack.com",),
    "github": ("github.com", "githubusercontent.com"),
    "okta": ("okta.com",),
    "salesforce": ("salesforce.com", "force.com"),
    "hmrc": ("hmrc.gov.uk", "gov.uk"),
    "irs": ("irs.gov",),
    "usps": ("usps.com",),
    "netflixbilling": ("netflix.com",),
}

# Flattened set of every legitimate brand domain, for fast membership tests.
LEGITIMATE_DOMAINS: frozenset[str] = frozenset(
    domain for domains in BRANDS.values() for domain in domains
)

# The apex domain most strongly associated with each brand keyword, used as the
# edit-distance reference point.
CANONICAL: dict[str, str] = {brand: domains[0] for brand, domains in BRANDS.items()}

# Consumer mailbox providers. Mail from these is not suspicious in itself, but
# corporate instructions arriving from one are.
FREEMAIL_DOMAINS: frozenset[str] = frozenset({
    "gmail.com", "googlemail.com", "yahoo.com", "yahoo.co.uk", "ymail.com",
    "hotmail.com", "hotmail.co.uk", "outlook.com", "live.com", "msn.com",
    "aol.com", "protonmail.com", "proton.me", "tutanota.com", "gmx.com",
    "gmx.de", "mail.com", "zoho.com", "yandex.com", "yandex.ru", "icloud.com",
    "me.com", "mail.ru", "inbox.lv", "rediffmail.com", "qq.com", "163.com",
})

# Domains offering disposable, no-signup mailboxes.
DISPOSABLE_DOMAINS: frozenset[str] = frozenset({
    "mailinator.com", "guerrillamail.com", "10minutemail.com", "temp-mail.org",
    "throwawaymail.com", "yopmail.com", "sharklasers.com", "trashmail.com",
    "getnada.com", "dispostable.com", "maildrop.cc", "fakeinbox.com",
})


def brand_for_domain(registered_domain: str) -> str | None:
    """Return the brand keyword that legitimately owns ``registered_domain``."""
    for brand, domains in BRANDS.items():
        if registered_domain in domains:
            return brand
    return None
