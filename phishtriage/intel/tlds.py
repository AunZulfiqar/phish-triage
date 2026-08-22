"""TLD, shortener and file-extension reference data.

The high-abuse TLD list reflects registries that have repeatedly appeared at the
top of public abuse rankings, generally because registration is free, bulk or
unverified. Presence on this list is a *weak* signal -- plenty of legitimate
sites use these TLDs -- which is why the corresponding indicator is weighted
low.
"""

from __future__ import annotations

HIGH_ABUSE_TLDS: frozenset[str] = frozenset({
    "zip", "mov", "tk", "ml", "ga", "cf", "gq", "xyz", "top", "buzz", "click",
    "link", "work", "rest", "country", "kim", "loan", "download", "racing",
    "win", "bid", "stream", "review", "date", "faith", "science", "party",
    "cricket", "accountant", "trade", "webcam", "men", "gdn", "cyou", "sbs",
    "quest", "monster", "icu", "bar", "beauty", "makeup", "skin", "hair",
})

URL_SHORTENERS: frozenset[str] = frozenset({
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd", "buff.ly",
    "adf.ly", "bit.do", "cutt.ly", "shorturl.at", "rebrand.ly", "rb.gy",
    "s.id", "tiny.cc", "shorte.st", "soo.gd", "clck.ru", "u.to", "v.gd",
    "lnkd.in", "trib.al", "t.ly", "short.io", "1url.com", "qr.ae",
})

# Query parameter names that commonly carry a follow-on absolute URL.
REDIRECT_PARAMS: frozenset[str] = frozenset({
    "url", "redirect", "redirect_uri", "redirect_url", "return", "returnurl",
    "return_to", "next", "target", "dest", "destination", "continue", "goto",
    "out", "link", "r", "u", "q", "forward", "callback", "checkout_url",
})

CREDENTIAL_PATH_TERMS: frozenset[str] = frozenset({
    "login", "signin", "sign-in", "log-in", "logon", "auth", "authenticate",
    "verify", "verification", "validate", "confirm", "confirmation", "secure",
    "security", "account", "accounts", "update", "unlock", "recover",
    "recovery", "reset", "password", "passwd", "credential", "session",
    "mfa", "2fa", "otp", "token", "webmail", "owa", "portal", "billing",
    "payment", "invoice", "wallet",
})

# --------------------------------------------------------------- attachments

EXECUTABLE_EXTENSIONS: frozenset[str] = frozenset({
    "exe", "scr", "com", "pif", "cpl", "msi", "msp", "mst", "dll", "sys",
    "drv", "ocx", "jar", "app", "gadget", "application", "deb", "rpm", "apk",
})

SCRIPT_EXTENSIONS: frozenset[str] = frozenset({
    "vbs", "vbe", "js", "jse", "wsf", "wsh", "ps1", "ps1xml", "ps2", "psc1",
    "psc2", "bat", "cmd", "hta", "reg", "scf", "sh", "py", "pl", "rb", "jsp",
    "php", "asp", "aspx", "chm", "inf", "msc",
})

MACRO_OFFICE_EXTENSIONS: frozenset[str] = frozenset({
    "docm", "dotm", "xlsm", "xltm", "xlam", "pptm", "potm", "ppam", "sldm",
    "xls", "doc", "ppt", "xlsb", "mht", "mhtml", "slk", "iqy",
})

ARCHIVE_EXTENSIONS: frozenset[str] = frozenset({
    "zip", "rar", "7z", "tar", "gz", "bz2", "xz", "cab", "arj", "lzh", "ace",
    "z", "tgz", "tbz",
})

CONTAINER_EXTENSIONS: frozenset[str] = frozenset({
    "iso", "img", "vhd", "vhdx", "dmg", "udf", "wim",
})

HTML_EXTENSIONS: frozenset[str] = frozenset({"html", "htm", "shtml", "xhtml", "svg"})

SHORTCUT_EXTENSIONS: frozenset[str] = frozenset({"lnk", "url", "website", "desktop"})

# Extensions people expect to be harmless, used as the visible half of a
# double extension.
DECOY_EXTENSIONS: frozenset[str] = frozenset({
    "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt", "rtf", "csv",
    "jpg", "jpeg", "png", "gif", "bmp", "mp3", "mp4", "avi", "mov", "zip",
    "html", "htm", "xml", "json", "eml", "msg",
})

# Canonical MIME type for common extensions, used for mismatch detection.
EXPECTED_MIME: dict[str, tuple[str, ...]] = {
    "pdf": ("application/pdf",),
    "zip": ("application/zip", "application/x-zip-compressed", "application/octet-stream"),
    "docx": ("application/vnd.openxmlformats-officedocument.wordprocessingml.document",),
    "xlsx": ("application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",),
    "pptx": ("application/vnd.openxmlformats-officedocument.presentationml.presentation",),
    "png": ("image/png",),
    "jpg": ("image/jpeg",),
    "jpeg": ("image/jpeg",),
    "gif": ("image/gif",),
    "txt": ("text/plain",),
    "html": ("text/html",),
    "htm": ("text/html",),
    "csv": ("text/csv", "application/csv", "text/plain"),
    "rtf": ("application/rtf", "text/rtf"),
    "xml": ("application/xml", "text/xml"),
}
