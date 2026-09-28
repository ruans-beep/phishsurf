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
3. **Discover independently, not just from what was generated.** crt.sh is
   searched with a prefix match on the brand token (`token%`) — this is a
   broad, independent search of crt.sh's own certificate database, not
   limited to the candidates generated in step 2, so it catches real
   squats regardless of how many edits away from the brand token they are.
   Any domain crt.sh or urlscan turns up that wasn't already generated
   gets folded into the candidate list before scoring, ahead of the
   generated ones (so it isn't crowded out by the raw candidate count when
   results get capped to the requested limit).
4. **Enrich**, failing soft on every lookup so one flaky source never kills
   the scan:
   - DNS A/AAAA/CNAME resolution for every candidate (generated + discovered)
   - [crt.sh](https://crt.sh) certificate transparency search (see above),
     filtered to the lookback window
   - [urlscan.io](https://urlscan.io) search for `page.domain` / `page.url`
     matches (works without a key; set `URLSCAN_API_KEY` for higher quota)
   - RDAP registration lookup on any domain that resolved or turned up in
     crt.sh/urlscan
   - A capped GET (8s timeout, 200KB body cap, no form submission) of the
     homepage for the top `FETCH_TOP_N` resolving hosts, looking for
     Shopify fingerprints, hotlinked official assets, and brand copy
5. **Score** each candidate 0–100 from named signals (see table below) and
   assign a label:
   `confirmed_lookalike_live`, `likely_clone_shop`, `cert_only_dormant`,
   `parked`, or `possible_false_positive`.
6. **Persist** the scan and its top-scored results to Postgres.

Only one scan runs at a time (enforced with a Postgres row lock); anything
submitted while a scan is running is queued and picked up automatically as
soon as the current scan finishes.

### Live watcher (`/brands`)

On-demand scans guess domains in advance and check if they exist — which
fundamentally can't cover every squat a determined registrant might pick
(see "Notes and limits" below). The live watcher takes the opposite
approach: instead of guessing, it tails a public
[certificate-transparency stream](https://certstream.calidog.io/) — every
domain that gets a new TLS certificate issued, anywhere, shows up on this
feed within seconds — and fuzzy-matches each one against your watched
brands. A match runs through the same DNS/RDAP/homepage-fetch enrichment
and scoring as an on-demand scan and gets persisted, so it catches real
squats the permutation generator could never predict, without you having
to find them manually first.

- Add a brand at `/brands`; it's matched from that point forward (not
  retroactively — the watcher only sees certificates issued after a brand
  is added).
- Matching uses [rapidfuzz](https://github.com/rapidfuzz/RapidFuzz)
  (`fuzz.ratio`) gated by a cheap 4-character-fragment prefilter, tuned
  against real squat examples — see `tests/test_fuzzy.py` for the exact
  domains used to pick `FUZZY_MATCH_THRESHOLD`.
- The `/brands` page shows live connection status (connected since, last
  certificate seen, message count) so a silently-stalled connection is
  visible instead of failing quietly. A `watcher heartbeat` line also logs
  every 5 minutes for the same reason.
- Runs as a background thread started at app startup; never blocks request
  handling or the app's healthcheck.

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
| `GET /brands` | Live watcher: watchlist + connection status, add a brand |
| `POST /brands` | Add a brand to the live watchlist |
| `POST /brands/{id}/toggle` | Pause/resume watching a brand |
| `GET /brands/{id}` | Hits the live watcher has found for a brand |
| `GET /health` | Unauthenticated health check |

## Stack

Python 3.12, FastAPI, Jinja2 + static CSS, SQLAlchemy + Postgres,
background scanning via FastAPI `BackgroundTasks` with a DB row lock, plus
a background-thread live watcher (`websocket-client` + `rapidfuzz`) tailing
a certificate-transparency stream.

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
| `MAX_CONCURRENCY` | no | `5` | Thread pool size for RDAP lookups and homepage fetches |
| `DNS_CONCURRENCY` | no | `25` | Thread pool size for DNS resolution (the dominant cost of a scan) |
| `CANDIDATE_HARD_CAP` | no | `3000` | Absolute ceiling on candidates per scan, regardless of the form |
| `DEFAULT_CANDIDATE_LIMIT` | no | `600` | Default "candidates to check" value on the new-scan form |
| `WATCH_ENABLED` | no | `true` | Set `false` to disable the live watcher entirely |
| `CERTSTREAM_URL` | no | `wss://certstream.calidog.io/` | Certificate-transparency stream the watcher tails |
| `FUZZY_MATCH_THRESHOLD` | no | `58` | Similarity threshold (0-100) for the watcher's fuzzy matcher |
| `WATCH_ENRICH_CONCURRENCY` | no | `5` | Thread pool size for enriching/scoring watcher matches |
| `BRAND_REFRESH_SECONDS` | no | `60` | How often the watcher re-reads the brand watchlist from the DB |

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

- Scan duration scales with the "candidates to check" value on the new-scan
  form (default `DEFAULT_CANDIDATE_LIMIT`, hard-capped at
  `CANDIDATE_HARD_CAP`): most candidates don't resolve, so each eats close
  to the full DNS timeout. At the defaults (600 candidates,
  `DNS_CONCURRENCY=25`) a scan finishes in a few minutes; pushing candidates
  toward the 3,000 ceiling can take 10+ minutes. Raise `DNS_CONCURRENCY` if
  your network tolerates more concurrent resolver queries.
- Every enrichment call fails soft — a missing crt.sh/urlscan/RDAP result
  lowers evidence for that candidate, it never aborts the scan.
- crt.sh discovery can surface a lot more real domains than the generated
  candidate list alone, especially against an active squat farm (seen in
  testing: 200+ real, independently-confirmed domains for one brand). If
  `candidate_count` on a finished scan is much larger than the "Result
  limit" you set, raise the limit and re-run — the discovered domains rank
  ahead of blind guesses already (they score higher, since they carry real
  certificate evidence), but ties past the limit get cut off.
- Candidate generation only covers close, single-edit-style lookalikes
  (edit-distance-1, adjacent-key typos, hyphenation, combosquat keywords,
  homoglyphs, TLD swaps) — this is intentional (see the scoring weights
  above) and won't catch a domain that's several edits away from the brand
  token or an unrelated-looking abbreviation. The edit-distance-1 and
  adjacent-key spaces are also far bigger than any practical per-scan
  budget (a ~14-character brand has ~12,000 possible single-edit domains
  alone), so generation randomly samples a different slice of that space
  on every scan rather than always checking the same subset — a specific
  real squat isn't guaranteed to turn up in any one run, but re-scanning
  periodically covers more ground over time. Raising "candidates to check"
  toward the 3,000 ceiling also raises the odds per scan, at the cost of
  scan time (see above).
- This tool surfaces candidates for a human to review. Scores are a
  triage aid, not a verdict — don't file a takedown, abuse report, or
  legal action from a score alone.
- **The live watcher depends on a free public third-party service**
  (`certstream.calidog.io`) that isn't operated by Bustem and isn't
  guaranteed uptime or throughput — its own history includes periods of
  degraded service. In testing, the websocket connection handshake
  succeeded but no certificates were observed in a sustained window,
  which could mean the service was quiet at that moment or genuinely
  degraded; this couldn't be fully verified from the dev environment used
  to build this. **Check `/brands` after deploying** — it shows connection
  status and a running count of certificates seen. If `messages_seen`
  stays at 0 for more than a few minutes after showing "connected", the
  upstream feed itself is the problem, not this app; the watcher will keep
  auto-reconnecting regardless, so it'll pick up on its own if/when the
  feed recovers. If it's unreliable long-term, `CERTSTREAM_URL` can be
  pointed at a self-hosted `certstream-server-go` instance instead.

## License

MIT — see [LICENSE](LICENSE).
