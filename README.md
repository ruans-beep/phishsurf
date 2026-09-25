# Phishsurf

Internal Bustem tool: paste a D2C brand domain, get back a scored list of
likely phishing / clone-shop / impersonator candidates with evidence links.
Not a public app — it's a small FastAPI web app behind a shared team
password.

> Candidates for human review. Do not file a takedown from score alone.

## How it works

1. **Normalize** the input domain with `tldextract`. The official apex and
   `www` subdomain are allowlisted and never reported.
2. **Generate lookalikes** (capped at 3,000 per scan): edit-distance-1
   mutations, adjacent-QWERTY-key substitutions, hyphenation, combosquat
   words (`shop`, `store`, `sale`, `login`, `checkout`, ...) across a set of
   TLDs (`com net org co io shop store online site app us co.uk`), plus
   homoglyph/punycode-style substitutions (flagged separately).
3. **Enrich**, failing soft on every lookup so one flaky source never kills
   the scan:
   - DNS A/AAAA/CNAME resolution for every candidate
   - [crt.sh](https://crt.sh) certificate transparency search for the brand
     token and lookalikes, filtered to the lookback window
   - [urlscan.io](https://urlscan.io) search for `page.domain` / `page.url`
     matches (works without a key; set `URLSCAN_API_KEY` for higher quota)
   - RDAP registration lookup on any domain that resolved or turned up in
     crt.sh/urlscan
   - A capped GET (8s timeout, 200KB body cap, no form submission) of the
     homepage for the top `FETCH_TOP_N` resolving hosts, looking for
     Shopify fingerprints, hotlinked official assets, and brand copy
4. **Score** each candidate 0–100 from named signals (see table below) and
   assign a label:
   `confirmed_lookalike_live`, `likely_clone_shop`, `cert_only_dormant`,
   `parked`, or `possible_false_positive`.
5. **Persist** the scan and its top-scored results to Postgres.

Only one scan runs at a time (enforced with a Postgres row lock); anything
submitted while a scan is running is queued and picked up automatically as
soon as the current scan finishes.

### Scoring weights

| Signal | Weight |
| --- | ---: |
| Brand token in host (≠ official) | +25 |
| Hotlinks official assets | +20 |
| Shopify fingerprint on foreign host | +20 |
| Combosquat keyword | +15 |
| Domain created in lookback window | +15 |
| Certificate issued in lookback window | +10 |
| Title/OG has brand | +10 |
| urlscan hit | +10 |
| Homoglyph | +8 |
| Edit-distance-1 | +8 |
| Let's Encrypt + newly created domain | +5 |
| Allowlisted (official domain) | −40 |
| News/wiki/app-store host | −25 |
| Parked, no brand content | −20 |
| Old domain, no clone content | −15 |

Score is clamped to 0–100.

## Pages

| Route | Purpose |
| --- | --- |
| `GET /login` | Password gate (signed cookie session) |
| `GET /` | New scan form: domain, lookback days, result limit |
| `POST /scans` | Create a scan job, redirects to its detail page |
| `GET /scans/{id}` | Status + results table, auto-refreshes while running |
| `GET /scans/{id}.json` | Download the scan as JSON |
| `GET /scans` | Scan history |
| `GET /health` | Unauthenticated health check |

## Stack

Python 3.12, FastAPI, Jinja2 + static CSS, SQLAlchemy + Postgres,
background scanning via FastAPI `BackgroundTasks` with a DB row lock.

## Local development

```bash
python -m venv .venv
source .venv/bin/activate   # .venv\Scripts\activate on Windows
pip install -r requirements.txt
cp .env.example .env        # then fill in APP_PASSWORD and SECRET_KEY
```

Without `DATABASE_URL` set, the app falls back to a local SQLite file
(`phishsurf.db`) — fine for local development, but use real Postgres in
production (Railway's Postgres plugin injects `DATABASE_URL` for you).

Run it:

```bash
uvicorn app.main:app --reload
```

Then open http://localhost:8000 and log in with `APP_PASSWORD`.

### Tests

```bash
pytest
```

`tests/test_permute.py` and `tests/test_scoring.py` cover candidate
generation and scoring/labeling directly — no database required.

## Environment variables

| Variable | Required | Default | Notes |
| --- | --- | --- | --- |
| `APP_PASSWORD` | yes | — | Shared team login password |
| `SECRET_KEY` | yes | — | Long random string, signs the auth cookie |
| `DATABASE_URL` | production | local SQLite | Injected automatically by Railway's Postgres plugin |
| `URLSCAN_API_KEY` | no | unset | Enables authenticated urlscan.io search |
| `LOOKBACK_DAYS_DEFAULT` | no | `30` | Default lookback window on the new-scan form |
| `FETCH_TOP_N` | no | `25` | How many resolving hosts get a homepage fetch |
| `MAX_CONCURRENCY` | no | `5` | Thread pool size for concurrent enrichment |

Generate a `SECRET_KEY` with:

```bash
python -c "import secrets; print(secrets.token_urlsafe(48))"
```

## Deploying to Railway

1. Push this repo to GitHub.
2. Railway → **New Project** → **Deploy from GitHub repo**.
3. Add the **Postgres** plugin to the project.
4. Set variables on the web service: `APP_PASSWORD`, `SECRET_KEY` (long
   random string). `DATABASE_URL` is injected automatically by the
   Postgres plugin — don't set it manually.
5. Generate a domain for the service and share the URL + password with the
   team.
6. Set the healthcheck path to `/health`.

Railway builds the included `Dockerfile` and runs:

```
uvicorn app.main:app --host 0.0.0.0 --port $PORT
```

(A `Procfile` with the same command is included for platforms that prefer
it over the Dockerfile CMD.)

## Notes and limits

- A scan with a large candidate pool can take several minutes: DNS
  resolution alone is `CANDIDATE_HARD_CAP` lookups at `MAX_CONCURRENCY`
  concurrency, and non-resolving domains eat their full timeout.
- Every enrichment call fails soft — a missing crt.sh/urlscan/RDAP result
  lowers evidence for that candidate, it never aborts the scan.
- This tool surfaces candidates for a human to review. Scores are a
  triage aid, not a verdict — don't file a takedown, abuse report, or
  legal action from a score alone.

## License

MIT — see [LICENSE](LICENSE).
