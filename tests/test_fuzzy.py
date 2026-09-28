from app.fuzzy import is_match, match_score

TOKEN = "bloomnutrition"

# Real domains a human found manually that the permutation-based scanner
# could not generate (they're multiple edits away from the brand token).
# The live watcher's whole purpose is to catch exactly these without
# needing to predict them in advance.
KNOWN_SQUATS = [
    "bloomnuue",
    "bloomnuus",
    "bloomnuua",
    "bloomwnutrltionw",
    "bloomtnutrition",
    "shopbloomnutrition",
    "bloomnutritionofficial",
    "bloomnutritiononline",
]

# Domains that share some surface similarity but are unrelated brands/words
# and must not flood the queue.
UNRELATED = [
    "google",
    "facebook-login",
    "bloomberg",
    "bloomingdales",
    "randomshop123",
    "bloomenergy",
]


def test_known_real_squats_all_match():
    for squat in KNOWN_SQUATS:
        assert is_match(squat, TOKEN), f"expected {squat!r} to match {TOKEN!r}"


def test_unrelated_brands_do_not_match():
    for domain in UNRELATED:
        assert not is_match(domain, TOKEN), f"expected {domain!r} not to match {TOKEN!r}"


def test_exact_token_matches():
    assert is_match(TOKEN, TOKEN)


def test_empty_strings_never_match():
    assert not is_match("", TOKEN)
    assert not is_match("something", "")
    assert not is_match("", "")


def test_no_shared_fragment_short_circuits_before_scoring():
    # Completely disjoint short strings share no 4-gram, so this must be
    # rejected by the prefilter regardless of what the raw ratio would say.
    assert not is_match("xyz", "abcdefgh")


def test_match_score_is_symmetric_and_bounded():
    score = match_score("bloomtnutrition", TOKEN)
    assert 0 <= score <= 100
    assert match_score("bloomtnutrition", TOKEN) == match_score(TOKEN, "bloomtnutrition")


def test_match_score_zero_for_empty_input():
    assert match_score("", TOKEN) == 0.0
    assert match_score("something", "") == 0.0
