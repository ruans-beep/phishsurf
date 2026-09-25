import os

APP_PASSWORD = os.environ.get("APP_PASSWORD", "")
SECRET_KEY = os.environ.get("SECRET_KEY", "dev-secret-change-me")

DATABASE_URL = os.environ.get("DATABASE_URL", "sqlite:///./phishsurf.db")

URLSCAN_API_KEY = os.environ.get("URLSCAN_API_KEY") or None

LOOKBACK_DAYS_DEFAULT = int(os.environ.get("LOOKBACK_DAYS_DEFAULT", "30"))
FETCH_TOP_N = int(os.environ.get("FETCH_TOP_N", "25"))
MAX_CONCURRENCY = int(os.environ.get("MAX_CONCURRENCY", "5"))

# Hard ceiling on how many lookalike candidates a single scan will generate
# and enrich, regardless of what the requester asks for.
CANDIDATE_HARD_CAP = int(os.environ.get("CANDIDATE_HARD_CAP", "3000"))

# Default number of top-scored results kept per scan when the requester
# doesn't specify a "limit" on the new-scan form.
DEFAULT_SCAN_LIMIT = int(os.environ.get("DEFAULT_SCAN_LIMIT", "40"))

COOKIE_NAME = "phishsurf_session"
COOKIE_MAX_AGE = 60 * 60 * 24 * 7  # 7 days
