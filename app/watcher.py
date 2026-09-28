"""Live watcher: tails a certificate-transparency stream (CertStream) and
fuzzy-matches every newly observed domain against the active brand
watchlist. A match runs through the same enrichment/scoring building
blocks the on-demand scanner uses (see enrich.py, scoring.py) and gets
persisted as a WatchHit — this is how the tool catches real squats that
the permutation-based scanner could never predict in advance.

Runs entirely in background threads, started once at app startup
(see main.py). Never blocks request handling.
"""
import json
import logging
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta

import websocket
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from . import config, enrich, fuzzy, permute
from .db import SessionLocal
from .models import Brand, WatchHit
from .scoring import Signals, score_result

logger = logging.getLogger("phishsurf.watcher")

_executor = None
_brands_cache = []
_brands_cache_at = 0.0

# Exposed via get_status() so /brands can show whether the live connection
# is actually up — this can't be assumed working just because the process
# is running (a network egress restriction, for example, would leave it
# silently hanging or endlessly reconnecting).
_status = {
    "enabled": False,
    "connected": False,
    "connected_at": None,
    "last_message_at": None,
    "messages_seen": 0,
    "last_error": None,
}


def get_status() -> dict:
    return dict(_status)


def start_watcher() -> None:
    """Launch the watcher in a background thread. Safe to call once at
    startup; a no-op if WATCH_ENABLED is false."""
    if not config.WATCH_ENABLED:
        logger.info("live watcher disabled (WATCH_ENABLED=false)")
        return
    _status["enabled"] = True
    global _executor
    _executor = ThreadPoolExecutor(max_workers=config.WATCH_ENRICH_CONCURRENCY)
    threading.Thread(target=_run_forever, daemon=True).start()
    threading.Thread(target=_heartbeat_forever, daemon=True).start()


def _heartbeat_forever() -> None:
    # A quiet connection (handshake succeeds but no messages ever arrive)
    # is a real failure mode for a third-party firehose like this and would
    # otherwise fail silently — log periodically so it shows up in
    # ordinary server logs, not just the /brands status banner.
    while True:
        time.sleep(300)
        logger.info(
            "watcher heartbeat: connected=%s messages_seen=%d last_message_at=%s",
            _status["connected"], _status["messages_seen"], _status["last_message_at"],
        )


def refresh_brands_now() -> None:
    """Force an immediate reload of the active brand list — called right
    after a brand is added/toggled so it takes effect without waiting for
    the periodic refresh."""
    _load_active_brands(force=True)


def _load_active_brands(force: bool = False):
    global _brands_cache, _brands_cache_at
    now = time.time()
    if not force and (now - _brands_cache_at) < config.BRAND_REFRESH_SECONDS:
        return _brands_cache
    try:
        with SessionLocal() as db:
            rows = db.execute(select(Brand).where(Brand.active.is_(True))).scalars().all()
            _brands_cache = [(b.id, b.domain, b.brand_token) for b in rows]
            _brands_cache_at = now
    except Exception:
        logger.exception("failed to refresh brand watchlist, keeping previous cache")
    return _brands_cache


def _on_open(_ws) -> None:
    logger.info("connected to certstream at %s", config.CERTSTREAM_URL)
    _status["connected"] = True
    _status["connected_at"] = datetime.utcnow().isoformat()
    _status["last_error"] = None


def _on_error(_ws, err) -> None:
    logger.warning("certstream error: %s", err)
    _status["last_error"] = str(err)


def _on_close(_ws, *_args) -> None:
    _status["connected"] = False


def _run_forever() -> None:
    backoff = 5
    while True:
        try:
            _load_active_brands(force=True)
            ws = websocket.WebSocketApp(
                config.CERTSTREAM_URL,
                on_open=_on_open,
                on_message=_on_message,
                on_error=_on_error,
                on_close=_on_close,
            )
            backoff = 5
            ws.run_forever(ping_interval=30, ping_timeout=10)
        except Exception as exc:
            logger.exception("certstream connection failed")
            _status["last_error"] = str(exc)
        _status["connected"] = False
        logger.info("certstream disconnected, reconnecting in %ss", backoff)
        time.sleep(backoff)
        backoff = min(backoff * 2, 120)


def _on_message(_ws, message: str) -> None:
    """Runs on the websocket's own thread — must stay cheap. Anything that
    touches the network or DB beyond the in-memory brand cache gets handed
    off to the enrichment thread pool.
    """
    _status["last_message_at"] = datetime.utcnow().isoformat()
    _status["messages_seen"] += 1

    try:
        payload = json.loads(message)
    except Exception:
        return
    if payload.get("message_type") != "certificate_update":
        return

    leaf = (payload.get("data") or {}).get("leaf_cert") or {}
    domains = leaf.get("all_domains") or []
    if not domains:
        return

    brands = _load_active_brands()
    if not brands:
        return

    for raw_domain in domains:
        domain = raw_domain.lower().lstrip("*.").strip()
        if not domain or "." not in domain:
            continue
        sld = permute.brand_token(domain)
        for brand_id, brand_domain, brand_token in brands:
            official_apex = permute.apex_domain(brand_domain)
            if domain in (official_apex, f"www.{official_apex}"):
                continue
            if fuzzy.is_match(sld, brand_token, config.FUZZY_MATCH_THRESHOLD):
                if _executor is not None:
                    _executor.submit(_handle_match, brand_id, brand_domain, brand_token, domain, leaf)
                break  # one brand match per observed domain is enough


def _handle_match(brand_id: str, brand_domain: str, brand_token: str, domain: str, leaf_cert: dict) -> None:
    try:
        with SessionLocal() as db:
            existing = db.execute(
                select(WatchHit.id).where(
                    WatchHit.brand_id == brand_id, WatchHit.candidate_domain == domain
                )
            ).scalar_one_or_none()
            if existing is not None:
                return

        apex = permute.apex_domain(brand_domain)
        allow = permute.allowlist_for(brand_domain)

        dns_info = enrich.resolve_dns(domain)
        resolves = bool(dns_info.get("a") or dns_info.get("aaaa") or dns_info.get("cname"))
        page = enrich.fetch_page(f"http://{domain}/", apex, brand_token) if resolves else {}
        rdap = enrich.rdap_lookup(domain) if resolves else {}

        created_dt = None
        if rdap.get("created"):
            try:
                created_dt = datetime.strptime(rdap["created"][:10], "%Y-%m-%d")
            except Exception:
                created_dt = None
        created_recently = bool(created_dt and created_dt >= datetime.utcnow() - timedelta(days=30))

        signals = Signals(
            brand_in_host=bool(brand_token) and brand_token in domain.split(".")[0],
            hotlinks_official_assets=bool(page.get("hotlinks_official_assets")),
            shopify_fingerprint_foreign=bool(page.get("shopify_fingerprint")),
            combosquat_keyword=any(w in domain for w in permute.COMBOSQUAT_WORDS),
            domain_created_in_window=created_recently,
            cert_in_window=True,  # it just appeared on the live stream
            title_or_og_has_brand=bool(page.get("title_or_og_has_brand")),
            redirects_to_official=bool(page.get("redirects_to_official")),
            allowlisted=domain in allow,
            parked_no_brand_content=(
                resolves
                and bool(page.get("reachable"))
                and not page.get("redirected_off_domain")
                and not page.get("title_or_og_has_brand")
                and not page.get("shopify_fingerprint")
                and not page.get("hotlinks_official_assets")
            ),
            resolves=resolves,
        )
        score, label, active_signals = score_result(signals)

        evidence = {
            "dns": dns_info,
            "rdap": rdap,
            "page": page,
            "certificate": {
                "not_before": leaf_cert.get("not_before"),
                "issuer": leaf_cert.get("issuer"),
            },
            "source": "certstream",
        }

        with SessionLocal() as db:
            db.add(WatchHit(
                brand_id=brand_id,
                candidate_domain=domain,
                match_score=round(fuzzy.match_score(permute.brand_token(domain), brand_token)),
                score=score,
                label=label,
                signals=active_signals,
                evidence=evidence,
            ))
            try:
                db.commit()
            except IntegrityError:
                db.rollback()  # same domain landed from a concurrent event first
    except Exception:
        logger.exception("failed to process watch hit for %s", domain)
