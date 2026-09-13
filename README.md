<p align="center">
  <h1 align="center">🛡️ PhishGuard API</h1>
  <p align="center">
    <strong>Intelligent Phishing URL Detection — Powered by Machine Learning & Multi-Layered Threat Analysis</strong>
  </p>
  <p align="center">
    <a href="https://phishguard-api.vercel.app">Live Demo</a> · <a href="#api-reference">API Docs</a> · <a href="#architecture">Architecture</a>
  </p>
</p>

---

PhishGuard is a full-stack phishing URL detection platform that combines a **Random Forest ML model**, **VirusTotal blacklist intelligence**, **WHOIS domain analysis**, and **heuristic pattern matching** into a single risk score. It ships with a sleek Next.js frontend and a FastAPI backend, deployed on **Vercel** as a monorepo.

## ✨ Features

- **4-Layer Detection Engine** — Blacklist, Pattern Heuristics, Domain Intelligence, and ML Classifier work together for zero false-negative coverage
- **Machine Learning** — Random Forest model trained on phishing datasets, with 17 engineered features including URL entropy, subdomain count, and brand impersonation signals
- **VirusTotal Integration** — Real-time cross-referencing against 70+ security vendor databases
- **WHOIS Domain Age** — Newly registered domains get escalated risk scores automatically
- **Typosquatting Detection** — Levenshtein distance-based detection catches `payytm.com`, `ggoogl.com`, and other deceptive misspellings
- **Brand Impersonation Guard** — Flags suspicious brand keywords on foreign domains (e.g., `paypal-login.xyz`)
- **Guest Mode** — Try the API without signup; authenticated users get 100 requests/day with analytics
- **Beautiful Frontend** — Animated UI with a WebGL splash cursor, glassmorphism cards, and real-time risk breakdowns
- **Deployed on Vercel** — Frontend (Next.js) + Backend (Python Serverless Functions) in one repo

## 🏗️ Architecture

```
phishguard-api/
├── frontend/                    # Monorepo root (deployed to Vercel)
│   ├── api/                     # Python backend (Vercel Serverless Functions)
│   │   ├── index.py             # FastAPI app entry point
│   │   ├── requirements.txt     # Python dependencies
│   │   ├── phishing_model.pkl.gz  # Trained ML model (~16 MB)
│   │   ├── label_encoder.pkl    # Scikit-learn label encoder
│   │   ├── detectors/           # Detection engine modules
│   │   │   ├── blacklist.py     # VirusTotal API integration
│   │   │   ├── pattern.py       # URL heuristic analysis
│   │   │   ├── domain.py        # WHOIS + SSL verification
│   │   │   ├── ml_model.py      # Random Forest feature extraction & prediction
│   │   │   └── scorer.py        # Multi-layer score aggregation & risk escalation
│   │   └── routes/              # API route handlers
│   │       ├── check.py         # POST /api/check-url
│   │       ├── auth.py          # POST /api/auth/signup, GET /api/auth/validate
│   │       └── analytics.py     # GET /api/analytics
│   ├── src/                     # Next.js frontend
│   │   ├── app/
│   │   │   ├── page.tsx         # Landing page
│   │   │   ├── layout.tsx       # Root layout (Geist font, Vercel Analytics)
│   │   │   ├── globals.css      # Design system & animations
│   │   │   └── components/
│   │   │       ├── Hero.tsx         # Animated hero section
│   │   │       ├── URLChecker.tsx   # Interactive URL scan widget
│   │   │       ├── HowItWorks.tsx   # Detection pipeline explainer
│   │   │       ├── BuildStory.tsx   # Project backstory
│   │   │       ├── APIDocs.tsx      # Interactive API documentation
│   │   │       ├── Footer.tsx       # Footer with links
│   │   │       └── SplashCursor.tsx # WebGL fluid cursor effect
│   │   └── lib/
│   │       └── types.ts         # TypeScript interfaces & risk level config
│   ├── package.json
│   ├── vercel.json              # API route rewrites
│   └── next.config.ts           # Dev proxy to local FastAPI
└── .env                         # Environment variables (not committed)
```

## 🔬 Detection Pipeline

Each URL is processed through 4 independent detection layers, and their scores are aggregated with weighted fusion + risk escalation rules:

| Layer | Weight | What It Does |
|-------|--------|-------------|
| **Blacklist (VirusTotal)** | 35% | Checks against 70+ AV engines. Requires ≥3 engines flagging at >5% ratio to avoid single-engine false positives |
| **ML Classifier** | 35% | Random Forest model with 17 features: URL length, entropy, digit count, brand impersonation, suspicious TLD, etc. |
| **Pattern Heuristics** | 20% | Regex-based checks for IP addresses, `@` symbols, excessive subdomains, phishing keywords, typosquatting |
| **Domain Intelligence** | 10% | WHOIS domain age (<30 days = high risk), SSL certificate validation with redirect-following |

**Risk Escalation Rules** are applied on top of the weighted score:
- Suspicious TLD (`.tk`, `.xyz`, `.click`, etc.) → +0.20
- Brand impersonation on foreign domain → +0.35
- Multiple phishing keywords → +0.15
- Domain age < 30 days → +0.25

**Final score** = `max(weighted_average, strongest_signal × 0.9)` — this prevents clean layers from diluting a single high-confidence detection.

## 🚀 Getting Started

### Prerequisites

- **Node.js** ≥ 18
- **Python** ≥ 3.9
- API keys for [VirusTotal](https://www.virustotal.com/gui/join-us), [IP2WHOIS](https://www.ip2whois.com/), and a [Supabase](https://supabase.com/) project

### 1. Clone the Repository

```bash
git clone https://github.com/HariomAcharya17/phishguard-api.git
cd phishguard-api
```

### 2. Set Up Environment Variables

Create a `.env` file in the project root:

```env
SUPABASE_URL=https://your-project.supabase.co
SUPABASE_KEY=your-supabase-anon-key
VIRUSTOTAL_API_KEY=your-virustotal-api-key
WHOIS_API_KEY=your-ip2whois-api-key
```

### 3. Install & Run the Backend

```bash
cd frontend/api
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn index:app --reload --port 8000
```

### 4. Install & Run the Frontend

```bash
cd frontend
npm install
npm run dev
```

Open [http://localhost:3000](http://localhost:3000) — the Next.js dev server proxies `/api/*` requests to the local FastAPI server.

### 5. Supabase Setup

Create two tables in your Supabase project:

**`api_keys`**
| Column | Type | Notes |
|--------|------|-------|
| id | uuid | Primary key, auto-generated |
| email | text | Unique |
| api_key | text | Unique, format: `pg_<uuid>` |
| requests | integer | Default: 0 |
| created_at | timestamptz | Default: now() |

**`analytics`**
| Column | Type | Notes |
|--------|------|-------|
| id | uuid | Primary key, auto-generated |
| api_key | text | Nullable (guest scans) |
| url | text | The scanned URL |
| risk_score | float | 0.0 – 1.0 |
| is_safe | boolean | true if risk_score < 0.25 |
| created_at | timestamptz | Default: now() |

## 📡 API Reference

### Check URL

```
POST /api/check-url
```

**Headers** (optional):
```
x-api-key: pg_your_api_key_here
```

**Body**:
```json
{
  "url": "https://example.com"
}
```

**Response**:
```json
{
  "url": "https://example.com",
  "is_safe": true,
  "risk_score": 0.0512,
  "risk_level": "safe",
  "threats_detected": [],
  "ml_score": 0.0,
  "domain_age_days": 10952,
  "recommendation": "This URL appears safe. No malicious signatures were detected.",
  "breakdown": {
    "blacklist": { "score": 0.0, "threats": [], "description": "..." },
    "pattern":   { "score": 0.0, "threats": [], "description": "..." },
    "domain":    { "score": 0.0, "threats": [], "description": "..." },
    "ml":        { "score": 0.0, "threats": ["..."], "description": "..." }
  }
}
```

### Sign Up for API Key

```
POST /api/auth/signup
```

```json
{ "email": "you@example.com" }
```

### Validate API Key

```
GET /api/auth/validate?api_key=pg_your_key
```

### Get Analytics Dashboard

```
GET /api/analytics
Headers: x-api-key: pg_your_key
```

## 🛠️ Tech Stack

| Component | Technology |
|-----------|-----------|
| Frontend | Next.js 16, React 19, TypeScript, Tailwind CSS v4, Framer Motion |
| Backend | FastAPI, Python 3.9+, Uvicorn |
| ML Model | Scikit-learn (Random Forest), Pandas, NumPy |
| Database | Supabase (PostgreSQL) |
| Threat Intel | VirusTotal API v3, IP2WHOIS API |
| Deployment | Vercel (Serverless Functions + Edge) |
| Analytics | Vercel Analytics |

## 🔒 Security Notes

- API keys are **never** exposed to the client — all requests are validated server-side
- Guest mode is available but rate-limited; authenticated users get 100 requests/day
- The `.env` file containing secrets is `.gitignore`'d and never committed
- CORS is configured to allow all origins (suitable for a public API)

## 📊 Risk Levels

| Score Range | Level | Meaning |
|------------|-------|---------|
| 0.00 – 0.14 | 🟢 **Safe** | No threats detected |
| 0.15 – 0.34 | 🟡 **Low** | Minor suspicious patterns |
| 0.35 – 0.64 | 🟠 **Medium** | Multiple phishing indicators |
| 0.65 – 0.84 | 🔴 **High** | Strong phishing characteristics |
| 0.85 – 1.00 | ☠️ **Critical** | Confirmed or highly likely phishing |

## 📝 License

This project is open source. Feel free to fork, modify, and use it for your own projects.

## 🤝 Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

---

<p align="center">
  Built with ❤️ by <a href="https://github.com/HariomAcharya17">Hariom Acharya</a>
</p>
