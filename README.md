# Samaritan

**Open-source global situational-awareness and OSINT workspace.** Samaritan
brings public-source geospatial feeds, tracking layers, incident context and
research tools together in one interactive MapLibre interface.

> Samaritan reuses the supplied project’s established application structure and feature modules, while replacing paid-service dependencies in its exposed integrations with local or no-cost alternatives.

## What is included

- **Global map workspace:** interactive MapLibre map, globe-style presentation,
  overlays, saved areas, filters, search and map controls.
- **Live public feeds:** aircraft, vessels, satellites, earthquakes, wildfires,
  weather and space-weather signals, news/events and public camera sources.
- **OSINT toolkit:** DNS, domain registration/RDAP, certificate transparency,
  BGP/ASN, IP metadata, CVE references, public host-index lookups and passive
  website/TLS inspection.
- **Entity intelligence:** Wikidata-linked entity expansion and OpenSanctions
  data for sanctions-name screening.
- **Chain intelligence:** public BTC/ETH/SOL explorer/RPC data and sanctions
  comparison, with optional free-tier enrichments.
- **OI assistant:** local Ollama by default, plus eligible free-tier Gemini and
  OpenRouter free models. Paid AI providers are not exposed in Samaritan's
  model picker.
- **Privacy-minded operation:** no sign-up or hosted account is needed; most
  data comes from upstream public feeds and is fetched as features are used.

Data availability, update cadence and geographic coverage vary by provider.
A public feed can be delayed, quota-limited, temporarily offline or restricted
by its terms. Samaritan displays source data; it does not independently verify
every public report or sensor observation.

## Free API policy

The baseline app does not require paid API access. It prioritises public,
keyless sources such as USGS, ADS-B feeds, GDELT/RSS, certificate-transparency
logs, public RDAP/DNS resolvers, CelesTrak, public blockchain explorers and
other open datasets already represented in the source code.

Optional credentials are supported only for integrations with a usable
public/free access path or a no-cost tier (for example selected Gemini models,
OpenSky account access, NASA FIRMS, N2YO, AIS Stream, Cloudflare Radar and
public blockchain data providers). They are **not required** for the baseline
experience. A free tier can still have request limits, eligibility
requirements, attribution obligations or terms that change. Do not enter or
enable paid plans when operating under a zero-cost requirement.

For AI:

| Provider | Cost model in Samaritan | Notes |
| --- | --- | --- |
| Ollama | Local inference; no API fee | Default provider; hardware and electricity are yours. |
| Google Gemini | Eligible free-tier model only | Requires a free-tier API key; subject to quota and data-use terms. |
| OpenRouter | Free router and `:free` models only | Low daily request limits; model availability changes. |
| Demo | Scripted development fallback | Not a real language model. |

The UI filters OpenRouter model choices to the free router and models ending
in `:free`. Do not add billing credits or select paid models if you intend to
keep cloud inference at zero cost. OI workflows can make multiple model calls,
so cloud quotas may be exhausted quickly; Ollama is recommended for heavier
use.

## Quick start — local development

Requirements: Node.js 22+, npm and (optionally) Docker Compose.

```bash
cp .env.example .env
# Generate a unique scanner secret (Linux/macOS): openssl rand -hex 32
# Paste it into SCANNER_KEY in .env before starting the scanner or Docker.
npm ci
```

Start each service in its own terminal:

```bash
# Terminal 1 — passive RECON sidecar
node --env-file=.env scanner/server.js

# Terminal 2 — entity intelligence sidecar
cd intel && npm ci && node --env-file=../.env server.js

# Terminal 3 — web app (from the repository root)
npm run dev
```

Open `http://localhost:3000`. Docker Compose is the recommended one-command
full-stack deployment.

## Docker

```bash
cp .env.example .env
# Set SCANNER_KEY in .env to a unique value of at least 32 characters.
# Generate one with: openssl rand -hex 32
docker compose up -d --build
```

See [DOCKER.md](DOCKER.md) for the full stack, Ollama options, configuration,
operations and security notes.

## Local AI with Ollama

Install Ollama on the host, then:

```bash
ollama pull qwen3:4b
```

For local non-Docker development, the provider defaults to
`http://127.0.0.1:11434/v1`. Docker Compose defaults to
`http://host.docker.internal:11434/v1` to reach Ollama on the host. On Linux,
configure host Ollama to listen on an address reachable from Docker and
restrict that port with your firewall. You can also choose `llama3.2:3b` or
`gemma3:4b` after pulling the model.

## Quality checks

```bash
npm run lint
npm test
npm run test:scanner
npm run build
```

Live upstream integration tests are available separately with
`npm run test:live`; they can be affected by provider availability and network
rate limits.

## Architecture

```text
Next.js / React / TypeScript
        │
        ├── public-data adapters ── public APIs, feeds and open datasets
        │
        ├── OI provider gateway ─── Ollama / free-tier Gemini / OpenRouter free
        │
        ├── samaritan-scanner ──── passive HTTP/TLS + public registry lookups
        │
        └── samaritan-intel ────── Wikidata + OpenSanctions entity resolution
```

The RECON and entity services are separate containers on a private Docker
network. Only the Next.js web application is exposed by the default Compose
file. No database is needed for the default deployment.

## Important limitations

- Public flight, vessel and camera coverage is source-dependent; the app cannot
  guarantee that a given object or camera is online.
- Public host-index results are indexed observations, not a live port scan.
  Passive software fingerprints and CVE keyword matches are leads, not proof
  of a vulnerability.
- IP geolocation is approximate and should not be treated as physical location.
- Sanctions-name matches can be false positives; they require human review.
- This project is for lawful research, monitoring and defensive analysis. Use
  the RECON tools only on systems you own or are authorised to assess.

## License and reuse

The repository retains the license file included with the supplied source
archive. Review that file and all upstream data-provider terms before
redistributing or deploying a modified copy.
