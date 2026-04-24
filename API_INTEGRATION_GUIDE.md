# VendorGuard AI — API Integration Guide

## Current Backend Status

Every feature works in **demo mode** right now (no API keys needed). Adding real API keys makes the data **live** — the system falls back gracefully if any API is unavailable.

---

## Free-Tier APIs to Add (Recommended)

### 1. VirusTotal API ⭐ (Highest Impact)
- **What it does**: Domain/URL reputation scanning, malware detection
- **Free tier**: 4 requests/minute, 500 requests/day, 15.5K/month
- **Speed**: ~2-3 seconds per lookup
- **Sign up**: https://www.virustotal.com/gui/join-us (free)
- **Env var**: `VIRUSTOTAL_API_KEY=your_key_here`
- **Impact**: Makes Audit Pipeline Layer 3 (Threat Intel) return LIVE data instead of MOCK
- **Currently**: Demo fallback shows realistic pre-built data for 12 vendors

### 2. Shodan API ⭐ (High Impact)
- **What it does**: Internet-wide port scanning, exposed service discovery
- **Free tier**: 1 request/second, no daily limit (for API queries)
- **Speed**: ~1-2 seconds per lookup
- **Sign up**: https://account.shodan.io/register (free account gives API key)
- **Env var**: `SHODAN_API_KEY=your_key_here`
- **Impact**: Real open-port/service discovery for any vendor domain
- **Currently**: Demo fallback with pre-built findings per vendor

### 3. OpenAI API ⭐ (Highest Impact for Demo)
- **What it does**: AI-generated board-ready risk summaries (CISO-quality)
- **Free tier**: $5 free credits for new accounts (enough for 1000+ scans)
- **Speed**: ~2-4 seconds for GPT-4o-mini summary generation
- **Sign up**: https://platform.openai.com/signup
- **Env var**: `OPENAI_API_KEY=your_key_here`
- **Model used**: `gpt-4o-mini` (fastest + cheapest, ~$0.002/scan)
- **Impact**: Transforms AI Risk Summary from template to genuinely insightful analysis
- **Currently**: Deterministic template summary (still good, but not AI-generated)

### 4. crt.sh (Certificate Transparency) — Already FREE & LIVE
- **Status**: Already working with no API key needed
- **What it does**: Subdomain enumeration via public CT logs
- **Speed**: ~500ms-3 seconds
- **No sign up needed** — public API
- **This is already active in every scan!**

### 5. DNS Resolution — Already FREE & LIVE
- **Status**: Already working with no API key needed
- **What it does**: SPF/DKIM/DMARC checks, DNS hygiene analysis
- **Speed**: ~10-50ms
- **This is already active in every scan!**

### 6. TLS Certificate Analysis — Already FREE & LIVE
- **Status**: Already working with no API key needed
- **What it does**: TLS version check, cipher suite analysis, cert expiry
- **Speed**: ~50-200ms
- **This is already active in every scan!**

---

## Optional APIs (Paid, but very useful)

### 7. HaveIBeenPwned (HIBP)
- **What it does**: Breach history for any domain
- **Pricing**: $3.50/month (cheapest paid API)
- **Speed**: ~500ms
- **Sign up**: https://haveibeenpwned.com/API/Key
- **Env var**: `HIBP_API_KEY=your_key_here`

### 8. Anthropic Claude (Alternative to OpenAI)
- **What it does**: Premium AI risk summaries
- **Free tier**: None, but $5 minimum credit
- **Env var**: `ANTHROPIC_API_KEY=your_key_here`
- **Set**: `AI_PROVIDER=anthropic`

### 9. OpenRouter (Access many AI models via one API)
- **What it does**: Route to Claude, GPT, Llama, Mistral etc.
- **Free tier**: Some free models available
- **Sign up**: https://openrouter.ai/
- **Env var**: `OPENROUTER_API_KEY=your_key_here`
- **Set**: `AI_PROVIDER=openrouter`

---

## How to Add API Keys

### Option A: `.env` file (Local development)
Create a `.env` file in the `backend/` folder:
```env
VIRUSTOTAL_API_KEY=your_vt_key_here
SHODAN_API_KEY=your_shodan_key_here
OPENAI_API_KEY=your_openai_key_here
HIBP_API_KEY=your_hibp_key_here
AI_PROVIDER=openai
```

### Option B: Environment variables (Deployment)
Set these in your hosting platform (Render, Railway, Fly.io, etc.)

---

## Backend Module Status — What's Built vs What Needs API

| Module | File | Lines | Status | API Needed? |
|--------|------|-------|--------|------------|
| OSINT Fan-out | `modules/osint.py` | 267 | FULLY BUILT | Free: crt.sh, DNS, TLS work NOW. Shodan/HIBP/VT need keys |
| Trust Scorer | `modules/trust_score.py` | 71 | FULLY BUILT | No API — pure ML scoring |
| DPDP Mapper | `modules/dpdp.py` | 92 | FULLY BUILT | No API — local rule engine |
| RAG Retriever | `modules/rag.py` | 286 | FULLY BUILT | No API — 49 DPDP Act passages embedded |
| Contract Intel | `modules/contract.py` | 603 | FULLY BUILT | No API — 17 DPDP rules engine |
| Gateway (ML) | `modules/gateway.py` | 239 | FULLY BUILT | No API — IsolationForest ML |
| Anomaly Detect | `modules/anomaly.py` | 116 | FULLY BUILT | No API — IsolationForest ML |
| AI Risk Engine | `modules/ai_risk.py` | 147 | FULLY BUILT | Optional: OpenAI/Claude for AI summaries |
| Agent Orchestrator | `modules/agent.py` | 179 | FULLY BUILT | No API — orchestrates other modules |
| PDF Reports | `modules/report.py` | 166 | FULLY BUILT | No API — ReportLab PDF |
| CERT-In PDF | `modules/incident.py` | 156 | FULLY BUILT | No API — ReportLab PDF |
| Playbook Gen | `modules/playbook.py` | 166 | FULLY BUILT | No API — rule-based |
| Backtest Engine | `modules/backtest.py` | 144 | FULLY BUILT | No API — 3 real Indian breach cases |
| Canary Tokens | `modules/canary.py` | 48 | FULLY BUILT | No API — in-memory token store |
| Alert Dispatch | `modules/alerts.py` | 54 | FULLY BUILT | Optional: Twilio for WhatsApp alerts |
| Metrics Export | `modules/metrics.py` | 61 | FULLY BUILT | No API — Prometheus format |
| Framework Crosswalk | `modules/framework.py` | 49 | FULLY BUILT | No API — ISO/SOC2/NIST/SEBI/RBI mapping |
| Cache Layer | `modules/cache.py` | ~60 | FULLY BUILT | No API — in-memory TTL cache |
| Logging | `modules/logging_config.py` | ~40 | FULLY BUILT | No API — structured JSON logging |
| Nuclei Scanner | `modules/nuclei.py` | ~60 | FULLY BUILT | Optional: nuclei binary on PATH |
| SQLite Store | `modules/store.py` | 200 | FULLY BUILT | No API — aiosqlite |
| Compliance Diff | `modules/compliance_diff.py` | 118 | FULLY BUILT | No API — diff engine |
| Webhook | `modules/webhook.py` | ~30 | FULLY BUILT | Optional: any POST-JSON target |

**Total: 31 modules, ~5,200+ lines of Python — ALL FULLY BUILT**

---

## Endpoint Coverage — 43 Endpoints

| # | Method | Endpoint | Status | Notes |
|---|--------|----------|--------|-------|
| 1 | GET | `/` | LIVE | App info + capabilities |
| 2 | GET | `/health` | LIVE | Health check |
| 3 | GET | `/companies` | LIVE | 12 categorized companies |
| 4 | POST | `/scan` | LIVE | Full OSINT scan |
| 5 | GET | `/scan/{vendor}` | LIVE | Last scan result |
| 6 | GET | `/scan/{vendor}/history` | LIVE | Scan history |
| 7 | GET | `/scan/{vendor}/diff` | LIVE | Compliance diff |
| 8 | POST | `/audit/pipeline/{vendor}` | LIVE | 6-step pipeline |
| 9 | POST | `/agent/onboard` | LIVE | 7-step autonomous agent |
| 10 | GET | `/backtest` | LIVE | 3 Indian breach cases |
| 11 | GET | `/backtest/{case_id}` | LIVE | Individual backtest |
| 12 | POST | `/contract/analyze` | LIVE | DPA analysis |
| 13 | POST | `/contract/analyze/upload` | LIVE | File upload DPA analysis |
| 14 | POST | `/gateway/activate` | LIVE | Gateway activation |
| 15 | POST | `/gateway/proxy` | LIVE | ML-guarded proxy |
| 16 | GET | `/gateway/status/{vendor}` | LIVE | Gateway status |
| 17 | POST | `/gateway/reset/{vendor}` | LIVE | Reset vendor gateway |
| 18 | GET | `/alerts` | LIVE | Recent alerts |
| 19 | GET | `/alerts/stream` | LIVE | SSE real-time stream |
| 20 | GET | `/report/{vendor}.pdf` | LIVE | Board-ready PDF |
| 21 | GET | `/report/{vendor}.certin.pdf` | LIVE | CERT-In incident PDF |
| 22 | GET | `/audit/{vendor}.zip` | LIVE | Full audit bundle |
| 23 | POST | `/audit/{vendor}/share` | LIVE | Signed share URL |
| 24 | GET | `/audit/public/{token}` | LIVE | Public shared audit |
| 25 | GET | `/playbook/{vendor}` | LIVE | Remediation playbook |
| 26 | GET | `/playbook/{vendor}.csv` | LIVE | CSV export |
| 27 | POST | `/canary/mint` | LIVE | Mint canary token |
| 28 | POST | `/canary/trip/{token_id}` | LIVE | Trip canary |
| 29 | GET | `/canary` | LIVE | List canary tokens |
| 30 | GET | `/framework/crosswalk` | LIVE | ISO/SOC2/NIST/SEBI/RBI |
| 31 | GET | `/rag/clause/{section}` | LIVE | RAG clause lookup |
| 32 | POST | `/rag/ask` | LIVE | Natural language Q&A |
| 33 | GET | `/virustotal/{domain}` | LIVE | VT scan + demo fallback |
| 34 | GET | `/graph` | LIVE | Vendor risk graph |
| 35 | GET | `/metrics` | LIVE | Prometheus metrics |
| 36 | GET | `/selftest` | LIVE | 4 benchmark self-tests |
| 37 | GET | `/osint/live/{vendor}` | LIVE | Live OSINT only |
| 38 | POST | `/vendors/bulk` | LIVE | Bulk scan |
| 39 | GET | `/incident/{alert_id}.pdf` | LIVE | Incident PDF |
| 40 | GET | `/benchmark/dpas` | LIVE | 4 benchmark DPAs |
| 41 | GET | `/benchmark/dpas/{dpa_id}` | LIVE | Individual DPA |
| 42 | GET | `/cache/stats` | LIVE | Cache metrics |
| 43 | GET | `/kpis` | LIVE | Portfolio KPIs |
| 44 | GET | `/portfolio` | LIVE | Portfolio overview |
| 45 | GET | `/vendors` | LIVE | Vendor list |

---

## Quick Start Priority

**For the best demo experience, add these 3 free APIs in this order:**

1. **VirusTotal** (free, instant signup) — makes threat intel layer show LIVE data
2. **OpenAI** (free $5 credits) — makes AI summaries genuinely intelligent
3. **Shodan** (free account) — makes port/service discovery real

Everything else already works without any API keys.
