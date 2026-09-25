"""Network enrichment for a candidate domain. Every function here fails
soft: on any error it returns an empty/falsy result instead of raising, so
one flaky lookup never aborts a whole scan.
"""
import re
from datetime import datetime
from html.parser import HTMLParser

import dns.resolver
import requests

from . import config

DNS_TIMEOUT = 4
HTTP_TIMEOUT = 8
MAX_BODY_BYTES = 200_000
USER_AGENT = "PhishsurfBot/1.0 (+internal Bustem brand-protection scanner)"

SHOPIFY_MARKERS = ("cdn.shopify.com", "shopify.theme", "/cdn/shop/", "shopify-analytics", "x-shopid")
BRAND_COPY_RE = re.compile(r"official store|% ?off|percent off", re.IGNORECASE)


def resolve_dns(domain: str) -> dict:
    out = {"a": [], "aaaa": [], "cname": None}
    resolver = dns.resolver.Resolver()
    resolver.timeout = DNS_TIMEOUT
    resolver.lifetime = DNS_TIMEOUT
    for rtype, key in (("A", "a"), ("AAAA", "aaaa")):
        try:
            answer = resolver.resolve(domain, rtype)
            out[key] = sorted({r.to_text() for r in answer})
        except Exception:
            pass
    try:
        answer = resolver.resolve(domain, "CNAME")
        out["cname"] = answer[0].to_text().rstrip(".")
    except Exception:
        pass
    return out


def crtsh_search(query: str, since: datetime) -> list:
    try:
        resp = requests.get(
            "https://crt.sh/",
            params={"q": query, "output": "json"},
            timeout=HTTP_TIMEOUT,
            headers={"User-Agent": USER_AGENT},
        )
        resp.raise_for_status()
        rows = resp.json()
    except Exception:
        return []

    out = []
    for row in rows or []:
        not_before_raw = row.get("not_before")
        if not not_before_raw:
            continue
        try:
            not_before = datetime.strptime(not_before_raw.split("T")[0], "%Y-%m-%d")
        except Exception:
            continue
        if not_before < since:
            continue
        out.append({
            "name": (row.get("name_value") or "").lower(),
            "issuer": row.get("issuer_name", ""),
            "not_before": not_before_raw,
        })
    return out


def urlscan_search(brand_token: str, exclude: set, since: datetime) -> list:
    headers = {"User-Agent": USER_AGENT}
    if config.URLSCAN_API_KEY:
        headers["API-Key"] = config.URLSCAN_API_KEY

    query = f"page.domain:*{brand_token}* OR page.url:*{brand_token}*"
    try:
        resp = requests.get(
            "https://urlscan.io/api/v1/search/",
            params={"q": query, "size": 100},
            headers=headers,
            timeout=HTTP_TIMEOUT,
        )
        resp.raise_for_status()
        data = resp.json()
    except Exception:
        return []

    out = []
    for r in data.get("results", []):
        page = r.get("page", {})
        pdomain = (page.get("domain") or "").lower()
        if not pdomain or pdomain in exclude:
            continue
        ts = (r.get("task") or {}).get("time")
        if ts:
            try:
                scanned = datetime.strptime(ts.split(".")[0], "%Y-%m-%dT%H:%M:%S")
                if scanned < since:
                    continue
            except Exception:
                pass
        out.append({"domain": pdomain, "url": page.get("url"), "result": r.get("result")})
    return out


def rdap_lookup(domain: str) -> dict:
    try:
        resp = requests.get(
            f"https://rdap.org/domain/{domain}",
            timeout=HTTP_TIMEOUT,
            headers={"User-Agent": USER_AGENT},
        )
        if resp.status_code != 200:
            return {}
        data = resp.json()
    except Exception:
        return {}

    created = None
    for event in data.get("events", []):
        if event.get("eventAction") == "registration":
            created = event.get("eventDate")
            break

    registrar = None
    for entity in data.get("entities", []):
        if "registrar" in (entity.get("roles") or []):
            vcard = entity.get("vcardArray")
            if vcard and len(vcard) > 1:
                for field in vcard[1]:
                    if field[0] == "fn":
                        registrar = field[3]
                        break

    return {"created": created, "registrar": registrar}


class _PageParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.title = ""
        self._in_title = False
        self.og = {}
        self.asset_urls = []

    def handle_starttag(self, tag, attrs):
        attrs_d = dict(attrs)
        if tag == "title":
            self._in_title = True
        if tag == "meta":
            prop = attrs_d.get("property") or attrs_d.get("name")
            if prop and prop.startswith("og:"):
                self.og[prop] = attrs_d.get("content", "")
        if tag in ("img", "script", "link"):
            src = attrs_d.get("src") or attrs_d.get("href")
            if src:
                self.asset_urls.append(src)

    def handle_endtag(self, tag):
        if tag == "title":
            self._in_title = False

    def handle_data(self, data):
        if self._in_title:
            self.title += data


def fetch_page(url: str, official_apex: str, brand_token: str) -> dict:
    try:
        resp = requests.get(
            url,
            timeout=HTTP_TIMEOUT,
            headers={"User-Agent": USER_AGENT},
            stream=True,
            allow_redirects=True,
        )
        body = b""
        for chunk in resp.iter_content(8192):
            if not chunk:
                break
            body += chunk
            if len(body) >= MAX_BODY_BYTES:
                break
        text = body.decode(resp.encoding or "utf-8", errors="ignore")
        status_code = resp.status_code
    except Exception:
        return {"reachable": False}

    parser = _PageParser()
    try:
        parser.feed(text)
    except Exception:
        pass

    lower = text.lower()
    shopify_fingerprint = any(marker in lower for marker in SHOPIFY_MARKERS)
    hotlinks_official = any(official_apex in (asset or "").lower() for asset in parser.asset_urls)
    brand_copy = bool(BRAND_COPY_RE.search(lower))
    title_or_og_has_brand = bool(brand_token) and (
        brand_token in parser.title.lower()
        or any(brand_token in (v or "").lower() for v in parser.og.values())
    )

    return {
        "reachable": True,
        "status_code": status_code,
        "title": parser.title.strip()[:200],
        "og": parser.og,
        "shopify_fingerprint": shopify_fingerprint,
        "hotlinks_official_assets": hotlinks_official,
        "brand_copy": brand_copy,
        "title_or_og_has_brand": title_or_og_has_brand,
    }
