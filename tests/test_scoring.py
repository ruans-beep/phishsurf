from app.scoring import Signals, compute_score, label_for, score_result


def test_allowlisted_wins_regardless_of_other_signals():
    signals = Signals(
        allowlisted=True,
        brand_in_host=True,
        hotlinks_official_assets=True,
        shopify_fingerprint_foreign=True,
        resolves=True,
    )
    score, label, active = score_result(signals)
    assert label == "possible_false_positive"
    assert "allowlisted" in active


def test_redirects_to_official_is_not_a_clone_even_with_other_signals_firing():
    # A domain that just forwards to the real brand site (common for
    # defensive registrations) must never be labeled as a clone, no matter
    # what else lines up (brand in host, cert issued in window, etc).
    signals = Signals(
        redirects_to_official=True,
        brand_in_host=True,
        combosquat_keyword=True,
        domain_created_in_window=True,
        cert_in_window=True,
        resolves=True,
    )
    score, label, active = score_result(signals)
    assert label == "possible_false_positive"
    assert "redirects_to_official" in active


def test_confirmed_lookalike_live_requires_brand_in_host_and_strong_evidence():
    signals = Signals(
        brand_in_host=True,
        hotlinks_official_assets=True,
        shopify_fingerprint_foreign=True,
        title_or_og_has_brand=True,
        domain_created_in_window=True,
        cert_in_window=True,
        resolves=True,
    )
    score, label, active = score_result(signals)
    assert label == "confirmed_lookalike_live"
    assert score == 100  # clamped: sum of active weights exceeds 100


def test_likely_clone_shop_without_brand_in_host():
    signals = Signals(
        hotlinks_official_assets=True,
        title_or_og_has_brand=True,
        resolves=True,
    )
    score, label, active = score_result(signals)
    assert label == "likely_clone_shop"
    assert score == 20 + 10


def test_cert_only_dormant_when_not_resolving():
    signals = Signals(cert_in_window=True, resolves=False)
    score, label, active = score_result(signals)
    assert label == "cert_only_dormant"
    assert score == 10


def test_parked_when_resolving_with_no_brand_content():
    signals = Signals(resolves=True, parked_no_brand_content=True)
    score, label, active = score_result(signals)
    assert label == "parked"
    assert score == max(0, -20)  # clamped to 0


def test_possible_false_positive_default():
    signals = Signals()
    score, label, active = score_result(signals)
    assert label == "possible_false_positive"
    assert score == 0
    assert active == []


def test_compute_score_sums_only_active_weighted_signals():
    signals = Signals(edit_distance_1=True, homoglyph=True, urlscan_hit=True)
    assert compute_score(signals) == 8 + 8 + 10


def test_score_never_goes_negative():
    signals = Signals(allowlisted=True, news_wiki_app_store=True, parked_no_brand_content=True)
    assert compute_score(signals) == 0


def test_score_never_exceeds_100():
    signals = Signals(**{name: True for name in [
        "brand_in_host", "hotlinks_official_assets", "shopify_fingerprint_foreign",
        "combosquat_keyword", "domain_created_in_window", "cert_in_window",
        "title_or_og_has_brand", "urlscan_hit", "homoglyph", "edit_distance_1",
        "letsencrypt_new_domain",
    ]})
    assert compute_score(signals) == 100


def test_label_for_is_pure_function_of_signals():
    signals = Signals(resolves=True, hotlinks_official_assets=True, brand_in_host=True)
    assert label_for(signals) == "confirmed_lookalike_live"
