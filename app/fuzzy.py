"""Fuzzy brand-name matching for the live certificate-stream watcher.

Pure module (no DB/network) so it's unit tested directly — see
tests/test_fuzzy.py. Thresholds here were tuned against real examples,
not guessed: see that test file for the exact squats/unrelated-domains
pairs used to pick them.
"""
from rapidfuzz import fuzz

NGRAM_SIZE = 4
DEFAULT_THRESHOLD = 58.0


def _ngrams(s: str, n: int = NGRAM_SIZE) -> set:
    if len(s) < n:
        return {s} if s else set()
    return {s[i:i + n] for i in range(len(s) - n + 1)}


def match_score(candidate_sld: str, brand_token: str) -> float:
    """Full-string similarity ratio (0-100) between a candidate domain's
    second-level label and a watched brand token."""
    if not candidate_sld or not brand_token:
        return 0.0
    return fuzz.ratio(brand_token, candidate_sld)


def is_match(candidate_sld: str, brand_token: str, threshold: float = DEFAULT_THRESHOLD) -> bool:
    """Whether a candidate domain label is a plausible squat of brand_token.

    Two-stage check:
    1. A cheap structural prefilter — the candidate must share at least one
       4-character fragment with the brand token. This is what a genuine
       squat almost always does (some recognizable chunk of the brand
       survives the mangling) and it's fast enough to run on every domain
       seen on a live certificate-transparency stream before bothering with
       the full similarity computation.
    2. A full-string similarity ratio threshold. Generic words that happen
       to share a fragment with the brand (e.g. another company also
       containing "nutrition") can still clear this — that's an accepted
       tradeoff for a "candidates for human review" tool: a few benign
       near-misses in the queue beats silently missing real squats.
    """
    if not candidate_sld or not brand_token:
        return False
    if candidate_sld == brand_token:
        return True
    if not (_ngrams(candidate_sld) & _ngrams(brand_token)):
        return False
    return match_score(candidate_sld, brand_token) >= threshold
