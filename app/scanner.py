"""Scan pipeline orchestration: candidate generation -> enrichment ->
scoring -> persistence, plus a Postgres row-lock so only one scan runs at a
time while others wait in the queue.
"""
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta

from sqlalchemy import select

from . import config, enrich, permute
from .db import SessionLocal
from .models import Result, Scan, ScanLock
from .scoring import Signals, score_result

logger = logging.getLogger("phishsurf.scanner")

NEWS_WIKI_APP_MARKERS = (
    "wikipedia.org", "wikimedia.org", "apps.apple.com", "play.google.com",
    "news.google.com", "reuters.com", "bloomberg.com", "nytimes.com",
)


def enqueue(scan_id: str) -> None:
    """Called right after a scan row is created. Drains the whole queue,
    not just this one scan, so a burst of submissions doesn't leave later
    jobs stranded waiting for a background task that never gets triggered.
    """
    process_queue()


def process_queue() -> None:
    while True:
        scan_id = _claim_next()
        if scan_id is None:
            return
        try:
            _run_scan(scan_id)
        except Exception as exc:  # pragma: no cover - defensive
            logger.exception("scan %s failed", scan_id)
            with SessionLocal() as db:
                scan = db.get(Scan, scan_id)
                if scan:
                    scan.status = "error"
                    scan.error_message = str(exc)
                    scan.finished_at = datetime.utcnow()
                    db.commit()
        finally:
            _release(scan_id)


def _claim_next():
    """Atomically claim the next queued scan under a row lock on the
    singleton ScanLock row, so concurrent requests can't both start a scan.
    """
    with SessionLocal() as db:
        lock = db.execute(
            select(ScanLock).where(ScanLock.id == 1).with_for_update()
        ).scalar_one()

        if lock.running_scan_id is not None:
            db.rollback()
            return None

        next_scan = db.execute(
            select(Scan).where(Scan.status == "queued").order_by(Scan.created_at).limit(1)
        ).scalar_one_or_none()
        if next_scan is None:
            db.rollback()
            return None

        next_scan.status = "running"
        next_scan.started_at = datetime.utcnow()
        lock.running_scan_id = next_scan.id
        db.commit()
        return next_scan.id


def _release(scan_id) -> None:
    if scan_id is None:
        return
    with SessionLocal() as db:
        lock = db.execute(select(ScanLock).where(ScanLock.id == 1).with_for_update()).scalar_one()
        if lock.running_scan_id == scan_id:
            lock.running_scan_id = None
            db.commit()
        else:
            db.rollback()


def _run_scan(scan_id: str) -> None:
    with SessionLocal() as db:
        scan = db.get(Scan, scan_id)
        domain, days, result_limit = scan.domain, scan.days, scan.limit
        candidate_limit = min(scan.candidate_limit or config.DEFAULT_CANDIDATE_LIMIT, config.CANDIDATE_HARD_CAP)

    apex = permute.apex_domain(domain)
    token = permute.brand_token(domain)
    allow = permute.allowlist_for(domain)
    since = datetime.utcnow() - timedelta(days=days)

    candidates = permute.generate_candidates(domain, limit=candidate_limit)

    # --- DNS resolution for every candidate ---
    # Plain resolver queries tolerate far more concurrency than the HTTP/RDAP
    # stages below, and this is the dominant cost of a scan (most candidates
    # don't resolve, so each eats a full DNS timeout) — so it gets its own,
    # higher-concurrency pool.
    dns_map = {}
    with ThreadPoolExecutor(max_workers=config.DNS_CONCURRENCY) as pool:
        futures = {pool.submit(enrich.resolve_dns, c["domain"]): c["domain"] for c in candidates}
        for fut in as_completed(futures):
            dns_map[futures[fut]] = fut.result()

    resolving = [
        c["domain"] for c in candidates
        if dns_map.get(c["domain"], {}).get("a")
        or dns_map.get(c["domain"], {}).get("aaaa")
        or dns_map.get(c["domain"], {}).get("cname")
    ]

    # --- Certificate transparency ---
    crt_hits_by_domain = {}
    for query in {token, apex}:
        for row in enrich.crtsh_search(f"%{query}%", since):
            name = row["name"].lstrip("*.").strip()
            if name:
                crt_hits_by_domain.setdefault(name, row)

    # --- urlscan.io ---
    urlscan_hits = {h["domain"] for h in enrich.urlscan_search(token, allow, since)}

    survivors = sorted(set(resolving) | set(crt_hits_by_domain.keys()) | urlscan_hits)

    # --- RDAP on survivors ---
    rdap_map = {}
    with ThreadPoolExecutor(max_workers=config.MAX_CONCURRENCY) as pool:
        futures = {pool.submit(enrich.rdap_lookup, d): d for d in survivors}
        for fut in as_completed(futures):
            rdap_map[futures[fut]] = fut.result()

    # --- Homepage fetch for the top N resolving hosts ---
    fetch_targets = resolving[: config.FETCH_TOP_N]
    page_map = {}
    with ThreadPoolExecutor(max_workers=config.MAX_CONCURRENCY) as pool:
        futures = {
            pool.submit(enrich.fetch_page, f"http://{d}/", apex, token): d
            for d in fetch_targets
        }
        for fut in as_completed(futures):
            page_map[futures[fut]] = fut.result()

    scored = _score_candidates(
        candidates, dns_map, crt_hits_by_domain, rdap_map, page_map, urlscan_hits, allow, since, token,
    )
    scored.sort(key=lambda row: row[0], reverse=True)
    top = scored[:result_limit]

    with SessionLocal() as db:
        scan = db.get(Scan, scan_id)
        scan.candidate_count = len(candidates)
        for score, cand_domain, label, active_signals, evidence in top:
            db.add(Result(
                scan_id=scan_id,
                candidate_domain=cand_domain,
                score=score,
                label=label,
                signals=active_signals,
                evidence=evidence,
            ))
        scan.status = "done"
        scan.finished_at = datetime.utcnow()
        db.commit()


def _score_candidates(candidates, dns_map, crt_hits_by_domain, rdap_map, page_map, urlscan_hits, allow, since, token):
    scored = []
    one_year_ago = since - timedelta(days=365)

    for c in candidates:
        d = c["domain"]
        dns_info = dns_map.get(d, {})
        resolves = bool(dns_info.get("a") or dns_info.get("aaaa") or dns_info.get("cname"))
        crt = crt_hits_by_domain.get(d)
        rdap = rdap_map.get(d, {})
        page = page_map.get(d, {})

        created_dt = None
        if rdap.get("created"):
            try:
                created_dt = datetime.strptime(rdap["created"][:10], "%Y-%m-%d")
            except Exception:
                created_dt = None

        created_in_window = bool(created_dt and created_dt >= since)
        old_domain = bool(created_dt and created_dt < one_year_ago)
        news_wiki = any(marker in d for marker in NEWS_WIKI_APP_MARKERS)

        signals = Signals(
            brand_in_host=bool(token) and token in _host_label(d),
            hotlinks_official_assets=bool(page.get("hotlinks_official_assets")),
            shopify_fingerprint_foreign=bool(page.get("shopify_fingerprint")),
            combosquat_keyword=bool(c.get("combosquat")),
            domain_created_in_window=created_in_window,
            cert_in_window=crt is not None,
            title_or_og_has_brand=bool(page.get("title_or_og_has_brand")),
            urlscan_hit=d in urlscan_hits,
            homoglyph=bool(c.get("homoglyph")),
            edit_distance_1=bool(c.get("edit_distance_1")),
            letsencrypt_new_domain=bool(
                crt and "let's encrypt" in (crt.get("issuer") or "").lower() and created_in_window
            ),
            allowlisted=d in allow,
            redirects_to_official=bool(page.get("redirects_to_official")),
            news_wiki_app_store=news_wiki,
            parked_no_brand_content=(
                resolves
                and bool(page.get("reachable"))
                and not page.get("redirected_off_domain")
                and not page.get("title_or_og_has_brand")
                and not page.get("shopify_fingerprint")
                and not page.get("hotlinks_official_assets")
            ),
            old_domain_no_clone_content=old_domain and not page.get("title_or_og_has_brand"),
            resolves=resolves,
        )
        score, label, active_signals = score_result(signals)

        evidence = {
            "dns": dns_info,
            "certificate": crt,
            "rdap": rdap,
            "urlscan_hit": d in urlscan_hits,
            "page": page,
            "technique": c.get("technique"),
        }
        scored.append((score, d, label, active_signals, evidence))

    return scored


def _host_label(domain: str) -> str:
    return domain.split(".")[0]
