"""Lookalike-domain candidate generation.

No database or network dependencies on purpose: this module is pure and unit
tested directly (see tests/test_permute.py).
"""
import re

import tldextract

COMBOSQUAT_WORDS = [
    "official", "shop", "store", "sale", "outlet", "deals", "vip", "hq",
    "usa", "login", "checkout", "secure", "get", "buy", "my",
]

TLDS = ["com", "net", "org", "co", "io", "shop", "store", "online", "site", "app", "us", "co.uk"]

QWERTY_ADJACENCY = {
    "q": "wa", "w": "qeas", "e": "wrds", "r": "etdf", "t": "ryfg", "y": "tugh",
    "u": "yihj", "i": "uojk", "o": "ipkl", "p": "ol",
    "a": "qwsz", "s": "awedxz", "d": "serfcx", "f": "drtgvc", "g": "ftyhbv",
    "h": "gyujnb", "j": "huikmn", "k": "jiolm", "l": "kop",
    "z": "asx", "x": "zsdc", "c": "xdfv", "v": "cfgb", "b": "vghn",
    "n": "bhjm", "m": "njk",
}

HOMOGLYPH_MAP = {"o": "0", "l": "1", "i": "1", "e": "3", "a": "4", "s": "5"}

ALPHABET = "abcdefghijklmnopqrstuvwxyz0123456789"

_VALID_LABEL = re.compile(r"^[a-z0-9-]+$")

# Priority order used when the candidate pool has to be truncated to the
# cap, so a small "limit" still yields a mix of techniques instead of being
# dominated by edit-distance noise.
TECHNIQUE_ORDER = ["combosquat", "tld_swap", "hyphenation", "homoglyph", "adjacent_key", "edit_distance_1"]

DEFAULT_HARD_CAP = 3000


def brand_token(domain: str) -> str:
    ext = tldextract.extract(domain)
    return (ext.domain or domain.split(".")[0]).lower()


def apex_domain(domain: str) -> str:
    ext = tldextract.extract(domain)
    parts = [p for p in (ext.domain, ext.suffix) if p]
    return ".".join(parts).lower() if parts else domain.lower()


def allowlist_for(domain: str) -> set:
    apex = apex_domain(domain)
    return {apex, f"www.{apex}"}


def _edit_distance_1(token: str) -> set:
    out = set()
    n = len(token)
    for i in range(n):
        out.add(token[:i] + token[i + 1:])  # deletion
    for i in range(n + 1):
        for c in ALPHABET:
            out.add(token[:i] + c + token[i:])  # insertion
    for i in range(n):
        for c in ALPHABET:
            if c != token[i]:
                out.add(token[:i] + c + token[i + 1:])  # substitution
    for i in range(n - 1):
        out.add(token[:i] + token[i + 1] + token[i] + token[i + 2:])  # transposition
    out.discard(token)
    out.discard("")
    return out


def _adjacent_key_subs(token: str) -> set:
    out = set()
    for i, ch in enumerate(token):
        for adj in QWERTY_ADJACENCY.get(ch, ""):
            out.add(token[:i] + adj + token[i + 1:])
    out.discard(token)
    return out


def _hyphenation_variants(token: str) -> set:
    return {token[:i] + "-" + token[i:] for i in range(1, len(token))}


def _combosquat_bases(token: str) -> set:
    out = set()
    for word in COMBOSQUAT_WORDS:
        out.add(f"{token}{word}")
        out.add(f"{word}{token}")
        out.add(f"{token}-{word}")
        out.add(f"{word}-{token}")
    return out


def _homoglyph_variants(token: str) -> set:
    out = set()
    chars = list(token)
    for i, ch in enumerate(chars):
        if ch in HOMOGLYPH_MAP:
            variant = chars.copy()
            variant[i] = HOMOGLYPH_MAP[ch]
            out.add("".join(variant))
    if "rn" in token:
        out.add(token.replace("rn", "m"))
    if "m" in token:
        out.add(token.replace("m", "rn"))
    out.discard(token)
    return out


def generate_candidates(official_domain: str, limit: int = DEFAULT_HARD_CAP) -> list:
    """Generate lookalike candidate domains for `official_domain`.

    Returns a list of dicts: {domain, technique, homoglyph, edit_distance_1,
    combosquat}. Capped at min(limit, DEFAULT_HARD_CAP) unique domains, with
    a round-robin across techniques so a small cap still samples every
    technique rather than being dominated by edit-distance noise.
    """
    token = brand_token(official_domain)
    allow = allowlist_for(official_domain)
    hard_cap = max(1, min(limit or DEFAULT_HARD_CAP, DEFAULT_HARD_CAP))

    technique_bases = {
        "edit_distance_1": [(b, False) for b in sorted(_edit_distance_1(token))],
        "adjacent_key": [(b, False) for b in sorted(_adjacent_key_subs(token))],
        "hyphenation": [(b, False) for b in sorted(_hyphenation_variants(token))],
        "combosquat": [(b, False) for b in sorted(_combosquat_bases(token))],
        "homoglyph": [(b, True) for b in sorted(_homoglyph_variants(token))],
        "tld_swap": [(token, False)],
    }

    results = {}
    idx = {t: 0 for t in TECHNIQUE_ORDER}
    progressed = True

    while progressed and len(results) < hard_cap:
        progressed = False
        for technique in TECHNIQUE_ORDER:
            bases = technique_bases[technique]
            i = idx[technique]
            if i >= len(bases):
                continue
            base, homoglyph = bases[i]
            idx[technique] += 1
            progressed = True

            base = base.strip("-")
            if not base or not _VALID_LABEL.match(base):
                continue

            for tld in TLDS:
                fqdn = f"{base}.{tld}"
                if fqdn in allow or fqdn in results:
                    continue
                results[fqdn] = {
                    "domain": fqdn,
                    "technique": technique,
                    "homoglyph": homoglyph,
                    "edit_distance_1": technique == "edit_distance_1",
                    "combosquat": technique == "combosquat",
                }
                if len(results) >= hard_cap:
                    break
            if len(results) >= hard_cap:
                break

    return list(results.values())
