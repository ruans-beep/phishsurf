import os

APP_PASSWORD = os.environ.get("APP_PASSWORD", "")
SECRET_KEY = os.environ.get("SECRET_KEY", "dev-secret-change-me")

DATABASE_URL = os.environ.get("DATABASE_URL", "sqlite:///./phishsurf.db")

URLSCAN_API_KEY = os.environ.get("URLSCAN_API_KEY") or None

LOOKBACK_DAYS_DEFAULT = int(os.environ.get("LOOKBACK_DAYS_DEFAULT", "30"))
FETCH_TOP_N = int(os.environ.get("FETCH_TOP_N", "25"))

# Thread pool size for RDAP lookups and homepage fetches — kept
# conservative because those hit real external servers/websites where
# politeness matters.
MAX_CONCURRENCY = int(os.environ.get("MAX_CONCURRENCY", "5"))

# Thread pool size for DNS resolution specifically. This is the dominant
# cost of a scan (most candidates don't resolve, so each eats a full DNS
# timeout) and plain resolver queries tolerate much higher concurrency
# than HTTP/RDAP calls do, so it gets its own, higher default.
DNS_CONCURRENCY = int(os.environ.get("DNS_CONCURRENCY", "25"))

# Hard ceiling on how many lookalike candidates a single scan will generate
# and enrich, regardless of what the requester asks for.
CANDIDATE_HARD_CAP = int(os.environ.get("CANDIDATE_HARD_CAP", "3000"))

# Default number of candidates a scan checks when the requester doesn't
# override it on the new-scan form. Kept well under CANDIDATE_HARD_CAP so
# a default scan finishes in a few minutes; raising it trades speed for
# broader coverage.
DEFAULT_CANDIDATE_LIMIT = int(os.environ.get("DEFAULT_CANDIDATE_LIMIT", "600"))

# Default number of top-scored results kept per scan when the requester
# doesn't specify a "limit" on the new-scan form.
DEFAULT_SCAN_LIMIT = int(os.environ.get("DEFAULT_SCAN_LIMIT", "40"))

COOKIE_NAME = "phishsurf_session"
COOKIE_MAX_AGE = 60 * 60 * 24 * 7  # 7 days

# Live watcher: tails a certificate-transparency stream and fuzzy-matches
# every newly observed domain against the brand watchlist, instead of
# guessing domains in advance like the on-demand scanner does.
WATCH_ENABLED = os.environ.get("WATCH_ENABLED", "true").strip().lower() not in ("false", "0", "")
CERTSTREAM_URL = os.environ.get("CERTSTREAM_URL", "wss://certstream.calidog.io/")
FUZZY_MATCH_THRESHOLD = float(os.environ.get("FUZZY_MATCH_THRESHOLD", "58"))

# Thread pool size for enriching/scoring watcher matches. Kept separate
# from MAX_CONCURRENCY since it's a different, continuously-running
# workload rather than a single scan's burst of work.
WATCH_ENRICH_CONCURRENCY = int(os.environ.get("WATCH_ENRICH_CONCURRENCY", "5"))

# How often (seconds) the watcher re-reads the active brand list from the
# database, so a newly added/removed brand takes effect without restarting.
BRAND_REFRESH_SECONDS = int(os.environ.get("BRAND_REFRESH_SECONDS", "60"))
