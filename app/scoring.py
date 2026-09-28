"""Signal weighting and labeling.

Pure module (no DB/network) so it's unit tested directly — see
tests/test_scoring.py.
"""
from dataclasses import dataclass

WEIGHTS = {
    "brand_in_host": 25,
    "hotlinks_official_assets": 20,
    "shopify_fingerprint_foreign": 20,
    "combosquat_keyword": 15,
    "domain_created_in_window": 15,
    "cert_in_window": 10,
    "title_or_og_has_brand": 10,
    "urlscan_hit": 10,
    "homoglyph": 8,
    "edit_distance_1": 8,
    "letsencrypt_new_domain": 5,
    "allowlisted": -40,
    "redirects_to_official": -30,
    "news_wiki_app_store": -25,
    "parked_no_brand_content": -20,
    "old_domain_no_clone_content": -15,
}

SIGNAL_FIELDS = list(WEIGHTS.keys())

LABELS = (
    "confirmed_lookalike_live",
    "likely_clone_shop",
    "cert_only_dormant",
    "parked",
    "possible_false_positive",
)


@dataclass
class Signals:
    brand_in_host: bool = False
    hotlinks_official_assets: bool = False
    shopify_fingerprint_foreign: bool = False
    combosquat_keyword: bool = False
    domain_created_in_window: bool = False
    cert_in_window: bool = False
    title_or_og_has_brand: bool = False
    urlscan_hit: bool = False
    homoglyph: bool = False
    edit_distance_1: bool = False
    letsencrypt_new_domain: bool = False
    allowlisted: bool = False
    redirects_to_official: bool = False
    news_wiki_app_store: bool = False
    parked_no_brand_content: bool = False
    old_domain_no_clone_content: bool = False

    # Informs labeling only; carries no weight of its own.
    resolves: bool = False

    def active(self) -> list:
        return [name for name in SIGNAL_FIELDS if getattr(self, name)]


def compute_score(signals: Signals) -> int:
    raw = sum(WEIGHTS[name] for name in signals.active())
    return max(0, min(100, raw))


def label_for(signals: Signals) -> str:
    if signals.allowlisted:
        return "possible_false_positive"

    # A candidate that just forwards to the real brand site isn't hosting
    # a clone — it's most likely a defensive registration pointed at the
    # official store. Its own page content never gets counted as clone
    # evidence (see enrich.fetch_page), but be explicit here too so this
    # can never be mislabeled even if other signals (cert, DNS) fire.
    if signals.redirects_to_official:
        return "possible_false_positive"

    live_clone_evidence = (
        signals.hotlinks_official_assets
        or signals.shopify_fingerprint_foreign
        or signals.title_or_og_has_brand
    )

    strong_clone_evidence = signals.hotlinks_official_assets or signals.shopify_fingerprint_foreign

    if signals.resolves and signals.brand_in_host and strong_clone_evidence:
        return "confirmed_lookalike_live"

    if signals.resolves and live_clone_evidence:
        return "likely_clone_shop"

    if signals.cert_in_window and not signals.resolves:
        return "cert_only_dormant"

    if signals.resolves and signals.parked_no_brand_content:
        return "parked"

    return "possible_false_positive"


def score_result(signals: Signals):
    """Returns (score, label, active_signal_names)."""
    score = compute_score(signals)
    label = label_for(signals)
    return score, label, signals.active()
