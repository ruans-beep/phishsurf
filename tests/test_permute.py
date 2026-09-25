from app.permute import (
    allowlist_for,
    apex_domain,
    brand_token,
    generate_candidates,
)


def test_brand_token_and_apex():
    assert brand_token("truniagen.com") == "truniagen"
    assert apex_domain("shop.truniagen.com") == "truniagen.com"
    assert apex_domain("truniagen.co.uk") == "truniagen.co.uk"


def test_allowlist_never_reported():
    candidates = generate_candidates("truniagen.com", limit=3000)
    domains = {c["domain"] for c in candidates}
    assert "truniagen.com" not in domains
    assert "www.truniagen.com" not in domains
    assert allowlist_for("truniagen.com") == {"truniagen.com", "www.truniagen.com"}


def test_generation_is_capped():
    candidates = generate_candidates("truniagen.com", limit=25)
    assert 0 < len(candidates) <= 25

    candidates = generate_candidates("truniagen.com", limit=500)
    assert len(candidates) <= 500

    # The hard ceiling always wins even if a caller asks for more.
    candidates = generate_candidates("truniagen.com", limit=10_000)
    assert len(candidates) <= 3000


def test_candidates_are_unique_and_well_formed():
    candidates = generate_candidates("truniagen.com", limit=800)
    domains = [c["domain"] for c in candidates]
    assert len(domains) == len(set(domains))
    for d in domains:
        assert d.count(".") >= 1
        label = d.rsplit(".", 1)[0]
        assert label  # never empty
        assert not label.startswith("-") and not label.endswith("-")


def test_small_cap_still_samples_every_technique():
    # A low cap used to be dominated entirely by edit-distance-1 noise;
    # the round-robin generator should surface every technique early.
    candidates = generate_candidates("truniagen.com", limit=60)
    techniques = {c["technique"] for c in candidates}
    assert {"combosquat", "tld_swap", "hyphenation", "homoglyph"} <= techniques


def test_combosquat_variants_present():
    candidates = generate_candidates("truniagen.com", limit=3000)
    domains = {c["domain"] for c in candidates}
    assert "truniagenshop.com" in domains
    assert "shop-truniagen.com" in domains


def test_tld_swap_present():
    candidates = generate_candidates("truniagen.com", limit=3000)
    domains = {c["domain"] for c in candidates}
    assert "truniagen.store" in domains
    assert "truniagen.shop" in domains


def test_homoglyph_flagged():
    candidates = generate_candidates("truniagen.com", limit=3000)
    homoglyphs = [c for c in candidates if c["homoglyph"]]
    assert homoglyphs
    assert all(c["technique"] == "homoglyph" for c in homoglyphs)


def test_edit_distance_and_adjacent_key_flagged():
    candidates = generate_candidates("truniagen.com", limit=3000)
    edit_distance = [c for c in candidates if c["edit_distance_1"]]
    assert edit_distance
    adjacent = [c for c in candidates if c["technique"] == "adjacent_key"]
    assert adjacent


def test_short_domain_does_not_crash():
    candidates = generate_candidates("ab.io", limit=200)
    assert isinstance(candidates, list)
