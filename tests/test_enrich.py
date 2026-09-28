from app.enrich import _looks_like_infra_error_page, content_mentions_brand


def test_multiword_brand_name_matches_despite_space():
    # Real example: token "bloomnu" (from bloomnu.us) vs the actual page
    # title "Bloom Nutrition" — a naive substring check misses this because
    # of the space, silently dropping a genuine brand match.
    assert content_mentions_brand("Bloom Nutrition", {}, "bloomnu")


def test_url_shaped_og_fields_are_not_content():
    # Real false positive: og:image trivially contains the domain's own
    # name (and therefore the token) regardless of actual page content.
    og = {"og:image": "https://bloomnubiteemporiumco.shop/opengraph-image.jpg?443c03a007878a5d"}
    assert not content_mentions_brand("Some Unrelated Page", og, "bloomnu")

    # og:url is equally self-referential.
    og2 = {"og:url": "https://bloomnubiteemporiumco.shop/"}
    assert not content_mentions_brand("Some Unrelated Page", og2, "bloomnu")


def test_non_url_og_fields_still_count():
    og = {"og:site_name": "Bloom Nutrition", "og:url": "https://example.com/"}
    assert content_mentions_brand("", og, "bloomnu")


def test_no_match_when_token_absent():
    assert not content_mentions_brand("Totally Unrelated Company", {}, "bloomnu")


def test_empty_token_never_matches():
    assert not content_mentions_brand("bloomnu everywhere", {}, "")


def test_infra_error_page_detected():
    assert _looks_like_infra_error_page("DNS resolution error | bloomnu.cc | Cloudflare")
    assert _looks_like_infra_error_page("Error 1001 | Cloudflare")
    assert not _looks_like_infra_error_page("Bloom Nutrition | Women's Health & Wellness Supplements")


def test_infra_error_page_title_does_not_match_brand_despite_echoing_domain():
    # Real false positive: Cloudflare's own error template restates the
    # requested domain (which contains the brand token) in its title —
    # that's the hosting provider talking, not the site's content.
    title = "DNS resolution error | bloomnu.cc | Cloudflare"
    assert content_mentions_brand(title, {}, "bloomnu")  # raw check: still "matches"
    assert _looks_like_infra_error_page(title)  # but this is what fetch_page gates on
