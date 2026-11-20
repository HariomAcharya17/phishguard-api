# PhishGuard

Phishing link checker and API. Paste a URL and get a verdict, a 0–100 risk score and a plain-language list of everything that was found.

Built by [Hariom Acharya](https://github.com/HariomAcharya17). Live at **[phishguard-api.vercel.app](https://phishguard-api.vercel.app)**.

## How a link is checked

| Layer | What it does |
|---|---|
| Reputation | VirusTotal (URL, then domain as a fallback), Google Safe Browsing, and the OpenPhish feed of active phishing URLs. A confirmed listing sets the score to at least 0.95. |
| Address rules | Brand names on unrelated domains or hidden in subdomains, look-alike spellings (`paypa1`, `g00gle`), IDN homoglyphs and mixed alphabets, text before `@`, raw or disguised IPs (`3232235777`, `0xC0A80101`), free hosting and tunnels, shorteners, risky downloads, open-redirect parameters, credential wording. |
| Domain records | WHOIS registration age, DNS resolution, HTTPS on the final page, and the real destination after redirects (followed server-side with SSRF protection). |
| Hostname model | Gradient-boosted trees over 20 hostname features, trained on the PhiUSIIL dataset. Stored as JSON and scored in pure Python. |

Each finding is a weighted signal. Signals are combined with noisy-OR, so independent evidence reinforces itself without simple addition running away. On well-known domains the address rules and model are damped (a bank's own login page legitimately says "login"); reputation feeds still apply in full.

### Measured performance (offline: address rules + model, no reputation lookups)

| Test set | Result |
|---|---|
| 300 live URLs from the OpenPhish feed (Nov 2026) | 81% flagged medium or higher |
| Tranco top 2,000 sites | 0% rated high or critical, 4.3% medium |
| Tranco ranks 50,000–52,000 | 0% high or critical, 2.7% medium |
| Hostname model, held-out domains | ROC AUC 0.88, precision 0.93 at 0.5 |

With reputation lookups enabled, links already known to feeds are caught regardless of how their address looks.

### Risk levels

| Score | Level | Shown as | Meaning |
|---|---|---|---|
| 0.00 – 0.19 | `safe` | Safe | No warning signs found |
| 0.20 – 0.39 | `low` | Low risk | Minor warning signs |
| 0.40 – 0.59 | `medium` | Suspicious | Several phishing traits |
| 0.60 – 0.79 | `high` | High risk | Likely phishing |
| 0.80 – 1.00 | `critical` | Dangerous | Phishing, or confirmed by a reputation feed |

## Project layout

```
frontend/                 Next.js site + Python API, deployed together on Vercel
  api/index.py            FastAPI app (routes /api/*)
  api/core.py             Supabase client, API keys, rate limits
  api/routes/             check-url, auth (signup/validate), analytics
  api/detectors/          urlparts, lexical, reputation, domain, netsafe, ml_model, scorer
  api/model/              domain_model.json (exported trees)
  src/app/                Website
ml/train_domain_model.py  Retrains the hostname model
supabase/schema.sql       Database tables
tests/                    pytest suite (offline)
```

## API

`POST /api/check-url` with `{"url": "..."}`. Optional header `X-API-Key`.

* Without a key: 10 checks per minute and 100 per day per IP.
* With a key: 100 checks per day.
* Interactive docs at `/api/docs`.

Other endpoints: `POST /api/auth/signup` (email → key, shown once), `GET /api/auth/validate?api_key=`, `GET /api/analytics` (header `X-API-Key`), `GET /api/health`.

## Environment variables

| Name | Required | Purpose |
|---|---|---|
| `VIRUSTOTAL_API_KEY` | recommended | VirusTotal lookups (free tier: 4 requests/min) |
| `GOOGLE_SAFE_BROWSING_KEY` | recommended | Safe Browsing lookups (free) |
| `WHOIS_API_KEY` | recommended | Domain age via ip2whois |
| `SUPABASE_URL`, `SUPABASE_KEY` | for API keys | Supabase project URL and **service-role** key |
| `OPENPHISH_DISABLED` | no | Set to `1` to skip the OpenPhish feed |
| `DAILY_KEY_LIMIT`, `GUEST_PER_MINUTE`, `GUEST_PER_DAY` | no | Limits (defaults 100 / 10 / 100) |

Every source is optional. A missing key or an outage is reported as "not checked" and never raises the score.

## Run locally

```bash
python -m venv .venv && .venv/bin/pip install -r frontend/api/requirements.txt uvicorn pytest
cd frontend && ../.venv/bin/uvicorn api.index:app --port 8000   # API
npm install && npm run dev                                      # site on :3000, proxies /api to :8000
```

Tests: `.venv/bin/python -m pytest tests` (no network or database needed).

## Database

Create a Supabase project and run `supabase/schema.sql` in the SQL editor.

## Retraining the model

```bash
.venv/bin/pip install pandas scikit-learn
.venv/bin/python ml/train_domain_model.py PhiUSIIL_Phishing_URL_Dataset.csv
```

Dataset: Prasad, A. & Chandra, S. (2023). *PhiUSIIL: A diverse security profile empowered phishing URL detection framework.* UCI Machine Learning Repository, id 967. Only hostnames are used, because every legitimate URL in the dataset is a bare homepage.

## Security notes

- Provider keys (VirusTotal, Safe Browsing, WHOIS, Supabase) are read only by the server and never sent to the browser.
- An existing API key is never returned on signup; it is shown once when created.
- Links are fetched server-side only to follow redirects. Every hop is resolved and private, loopback and cloud-metadata addresses are refused.
- CORS allows any origin without credentials, which suits a public API.
- `.env` files are git-ignored.

## License

Open source. Feel free to fork, modify and use it in your own projects.

## Contributing

1. Fork the repository.
2. Create a branch: `git checkout -b feature/your-change`.
3. Run the tests: `.venv/bin/python -m pytest tests`.
4. Commit, push and open a pull request.
