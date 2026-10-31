# Samaritan — Docker deployment

Samaritan is a self-hosted OSINT situational-awareness dashboard. The web app,
passive RECON service and entity-intelligence service are built from this
checkout. No paid API subscription is required for the baseline installation.

## Requirements

- Docker Engine 24+ and Docker Compose v2
- 4 GB RAM minimum; 8 GB+ recommended for local AI models
- An internet connection for public data sources

## Start

```bash
cp .env.example .env
# Generate a unique secret and put it in SCANNER_KEY in .env.
# Linux/macOS: openssl rand -hex 32

docker compose up -d --build
```

Open `http://localhost:3000` (or the port set by `SAMARITAN_PORT`). The Compose
stack starts three services:

| Service | Purpose | Host port |
| --- | --- | --- |
| `samaritan` | Next.js web application and API routes | 3000 |
| `samaritan-scanner` | Private, passive RECON service | Not published |
| `samaritan-intel` | Entity resolution and sanctions index | Not published |

All services share a private Compose network. The scanner secret is injected
into both web and scanner containers. Do not publish the scanner or
intelligence ports directly to the internet.

## Local AI (recommended)

The no-cost inference option is Ollama. Install it on the host, pull a model,
and let the app reach it through the Docker host gateway:

```bash
ollama pull qwen3:4b
# Compose defaults to host.docker.internal:11434
```

Alternatively, run Ollama as an optional Compose service. Set this in `.env`:

```env
SAMARITAN_OLLAMA_URL=http://samaritan-ollama:11434/v1
```

Then run:

```bash
docker compose --profile local-ai up -d --build
docker compose exec samaritan-ollama ollama pull qwen3:4b
```

Model quality and speed depend on available CPU, RAM and GPU. Small models
work for short summaries and tool assistance but may be less capable at
long multi-step forecasts.

## Free cloud AI providers

The OI model selector exposes local Ollama, eligible Gemini free-tier models,
and OpenRouter's free router / `:free` models. Cloud providers enforce their
own quotas and eligibility rules, which can change. Keep your account on its
no-cost tier and never select a paid model. Ollama is the only option that
does not depend on a third-party API quota.

## Configuration

| Variable | Purpose |
| --- | --- |
| `SAMARITAN_PORT` | Host port for the web interface (default `3000`). |
| `SCANNER_KEY` | Shared secret between web app and private RECON container. |
| `SAMARITAN_OLLAMA_URL` | OpenAI-compatible local Ollama endpoint. |
| `GEMINI_API_KEY_1` | Optional Gemini free-tier key for selected built-in AI features. |
| `CLOUDFLARE_API_TOKEN` | Optional Cloudflare Radar layer access. |
| `FIRMS_API_KEY` | Optional NASA FIRMS feed enhancement. |
| `OPENSKY_CLIENT_ID`, `OPENSKY_CLIENT_SECRET` | Optional OpenSky OAuth credentials for higher aircraft-feed limits. |
| `N2YO_API_KEY` | Optional satellite-pass feed key. |
| `AIS_API_KEY` | Optional AIS Stream key for maritime positions. |
| `ETHERSCAN_API_KEY`, `HELIUS_API_KEY` | Optional chain-intelligence enrichments; keyless base sources remain available. |

All cloud keys are optional enhancements. Public feeds have rate limits,
attribution requirements and availability constraints; a free account does
not mean unlimited usage.

## Operations

```bash
docker compose ps
docker compose logs -f samaritan
docker compose logs -f samaritan-scanner
docker compose logs -f samaritan-intel
docker compose up -d --build
docker compose down
```

Persistent Ollama model files are stored in the `ollama-data` volume. The web
app's transient caches and rate limits live in process memory. No database is
required for the default application.

## Security notes

- RECON requests are rate-limited and public/private target ranges are checked
  before the scanner receives them.
- The bundled RECON backend performs HTTP/TLS inspection and public registry
  lookups only. It does not brute-force, exploit, or perform wide port sweeps.
- The legacy port lookup now queries the read-only public InternetDB dataset;
  it is not an active port scan and a missing record is not proof of security.
- Set `SCANNER_KEY` to a unique printable secret of at least 32 characters
  before starting; the scanner rejects empty, short and placeholder keys. Put the web service behind HTTPS and a properly configured reverse
  proxy for public deployment.
- Free third-party API quotas and terms may change. Check provider policies
  before sustained or commercial workloads.
