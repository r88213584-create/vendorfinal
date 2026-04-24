# VendorGuard AI · Deploy for live-demo QR code

This recipe gets you a public URL in **under 15 minutes** so you can put a QR
code on your final slide and let judges scan their own domain live from their
phone. All four deploy targets below are pre-wired — pick one.

## TL;DR (Fly.io + Vercel — recommended for the hackathon)

```bash
# 1. Deploy the FastAPI backend to Fly.io (free tier)
cd backend
fly launch --name vendorguard-api --region bom  # Mumbai for Indian latency
fly secrets set DEMO_MODE=true                  # safe default for the hackathon
fly deploy

# 2. Deploy the static frontend to Vercel (free tier)
cd ../frontend
# Edit config.js and set:
#   window.VG_API = 'https://vendorguard-api.fly.dev';
vercel --prod

# 3. Grab the Vercel URL (e.g. https://vendorguard.vercel.app) and feed it to
#    any QR generator. The app already has a 🔗 QR button in the header that
#    generates one for the currently-loaded URL.
```

## Alternative: Render (single service, one click)

`render.yaml` is already in the repo. In Render dashboard:

1. New → Blueprint
2. Connect this repo
3. Environment: set `DEMO_MODE=true`, `CORS_ORIGINS=*`
4. Deploy. You get `https://vendorguard.onrender.com` serving both API and frontend.

## Alternative: Railway

`railway.json` is pre-wired. `railway up` deploys. Set the same env vars.

## Alternative: Docker / docker-compose (self-host on any VPS with a public IP)

```bash
docker compose up -d --build
```

Ports: backend 8765, frontend 8080. Put nginx / Caddy in front for TLS.

## Environment variables worth knowing

| Var | Default | What it does |
|---|---|---|
| `DEMO_MODE` | `false` | Enables the SSE live alerts loop + mock OSINT fallback so the scan path is deterministic under CI / on-stage |
| `CORS_ORIGINS` | `http://127.0.0.1:8080` | Comma-sep list of frontend origins allowed to call the API |
| `ALERT_WEBHOOK_URL` | *(unset)* | If set, every block alert is POSTed as a JSON payload (Slack, Teams, PagerDuty-events-API-compatible) |
| `VG_AUDIT_TTL_SECONDS` | `86400` | TTL for HMAC-signed audit-ZIP share links (24h default) |
| `VG_SIGNING_SECRET` | *(auto-generated in DEMO_MODE)* | HMAC secret for signed URLs — **set this to a proper 32-byte secret in prod** |

## Put a QR on your final slide

The app ships a QR generator. From the dashboard:
1. Click `🔗 QR` in the top-right of the header.
2. Copy the image or the URL into your slide deck.

That's it. On stage: "Scan this and type your own company's domain." Done.

## Healthcheck & smoke test

```bash
curl https://vendorguard-api.fly.dev/selftest | jq .passed   # -> 4
curl https://vendorguard-api.fly.dev/metrics | head         # -> Prometheus text
curl https://vendorguard-api.fly.dev/backtest | jq .cases[].id  # -> 3 cases
```

If any of these don't return the expected output, check `fly logs` (or the
equivalent for your target) for the actual error.
