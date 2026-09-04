# OpenVigie

OpenVigie is an open-source, asset-centric cybersecurity and vulnerability
intelligence platform.

Instead of showing another endless CVE feed, OpenVigie starts with the products
and versions that make up an infrastructure. It then correlates vendor
advisories, public vulnerability databases, exploitation signals, defensive
detection templates, and remediation guidance.

> **Project status:** early public prototype. Asset monitoring and the automatic
> source feed are functional, while the long-form editorial dossiers remain
> demonstration content. OpenVigie must not be treated as a production
> vulnerability assessment or as an automatically verified newsroom.

## Product principles

- **Asset first:** vendor, product, version, exposure, and business context.
- **Traceable:** every claim should link back to a primary or clearly identified
  public source.
- **Explainable:** show why an asset is considered affected and how the attack
  works at a defensive level.
- **Risk focused:** distinguish severity, active exploitation, public PoCs, and
  weaponized tooling.
- **Safe by design:** OpenVigie references public evidence but does not execute
  exploits.
- **Open:** auditable collectors, transparent matching rules, and community
  contributions.

## The OpenVigie Bulletin

The **Bulletin unifié** displays a curated feed of cybersecurity news and
vulnerabilities, refreshed every three hours from 44+ specialist RSS/Atom sources.

### Features

- **Article images** — cover images are extracted from feed enclosures, Media RSS
  metadata, or article HTML and displayed as lazy-loaded thumbnails in the feed.
- **Vigi — local AI assistant** — a chatbot powered by Qwen2.5 3B (100% local,
  runs in Docker) that answers questions about the bulletin and your asset
  inventory. Vigi correlates CVEs, exploitation status, and remediation guidance
  without sending data to external AI services.
- **Weekly report** (`/rapport-hebdo`) — synthesizes the past 7 days with:
  - Top CVE ranked by CISA KEV status and mention count;
  - Top news stories by relevance;
  - Trending keywords extracted from article titles and summaries;
  - Category breakdown (vulnerabilities, data breaches, threat campaigns, etc.);
  - One-click export to **PDF** and **HTML** for archival or sharing.

Two operational desks support infrastructure watch: **Software supply chain**
covers malicious packages, dependency risks, SBOM, build provenance, and
artifact signing; **VPN & remote access** covers edge appliances, SSL-VPN/IPsec
gateways, remote clients, and actively exploited perimeter vulnerabilities.

The collector refreshes feeds every three hours, stores article metadata in
SQLite, removes tracking parameters, detects CVE identifiers, classifies themes,
and keeps source diversity in automatic ranking. It runs continuously even when
the browser is closed.

OpenVigie stores only the title, author when supplied by the feed, a short
plain-text excerpt, dates, attribution, the original link, and a cover image URL
(when available). It does not copy article bodies or rewrite source claims. See
[EDITORIAL_POLICY.md](EDITORIAL_POLICY.md).

## Functional asset monitoring

The **My assets** workspace now lets users:

- add a vendor, product, installed version, local label, and exposure context;
- keep that inventory locally in the browser, without sending IP addresses or
  credentials;
- query NVD from the OpenVigie server using an exact CPE and version whenever a
  reliable mapping is available;
- correlate matching CVEs with the CISA Known Exploited Vulnerabilities catalog;
- filter by severity, exploitation status, CVE identifier, or description;
- open primary vendor advisories, patches, mitigations, and NVD evidence; and
- correlate recent CERT-FR alerts and security advisories with the monitored
  vendor, product, version, and matching CVE identifiers; and
- refresh every registered product/version snapshot automatically each day.

With Docker, a dedicated collector stores normalized snapshots in a SQLite
volume and continues refreshing monitored product/version queries while the
browser tab is closed. If NVD or CISA is temporarily unavailable, OpenVigie can
serve the latest known snapshot and mark it as stale.

The interface labels text-search fallback matches as lower confidence. Always
confirm affected and fixed version ranges in the linked vendor advisory before
changing production infrastructure.

OpenVigie works with the public NVD rate limit. For larger inventories, copy
`.env.example` to `.env`, add an optional `NVD_API_KEY`, and restart Docker.

## Live sources

- NVD / NIST CVE API 2.0 and CISA Known Exploited Vulnerabilities;
- CERT-FR / ANSSI alertes and avis as two dedicated bulletin pages, CISA
  Cybersecurity Advisories, and CERT-EU;
- NCSC UK, Cisco PSIRT, and Palo Alto Networks Security Advisories;
- OpenSSF and GitHub Supply Chain Security;
- SentinelLabs, Cisco Talos, Unit 42, CrowdStrike, ESET, Zero Day Initiative,
  watchTowr Labs, and PortSwigger Research;
- BleepingComputer, The Record, Krebs on Security, and Schneier on Security;
- ZATAZ cybersecurity news;
- **Anthropic Security** — AI safety and security research;
- **OpenAI Atlas** — AI editor updates and agent/model announcements;
- **Google Project Zero** — vulnerability research and disclosure;
- Freedom of the Press Foundation, Electronic Frontier Foundation, Access Now,
  Citizen Lab, Amnesty Security Lab, and Forbidden Stories;
- Microsoft Security Response Center, Google Security Blog, Mozilla Security,
  Cloudflare, and SANS Internet Storm Center; and
- linked vendor security advisories and patch references from matching CVEs.

Each feed has a visible synchronization state. An unavailable source is marked
as degraded without preventing the latest stored articles from being read.

The asset catalog covers network, firewall, VPN, EDR/XDR, server,
virtualization, storage, backup, and orchestration products from more than 25
vendors. Products without a reliable public CPE mapping use a visibly
lower-confidence text search and always link to the vendor security portal.

## Planned enrichments

- FIRST EPSS
- Additional vendor PSIRT advisories
- Exploit-DB / SearchSploit metadata
- Metasploit module metadata
- Nuclei template metadata

## Repository layout

```text
openvigie/
├── apps/
│   └── web/              Miami-inspired interface and API gateway
└── services/
    └── collector/        Scheduled NVD/CISA collection and SQLite cache
```

## Run the web prototype

### With Docker Desktop

From the repository root:

```bash
docker compose up --build
```

Then open `http://localhost:3000`. Stop the application with `Ctrl+C`, or run
`docker compose down` from another terminal.

### Local AI with Vigi (Ollama)

The Docker stack includes Ollama and Qwen2.5 3B Instruct. No host installation
is required on Windows, Linux, or macOS. Start the complete stack normally:

```bash
docker compose up -d --build
```

The `ollama-model` initialization container downloads the model on first start;
subsequent starts reuse the `openvigie_ollama` Docker volume. Ollama is exposed
only on the host loopback interface at `http://localhost:11434` and is available
to the web app at `http://ollama:11434`. To select another model or host port,
set `OLLAMA_MODEL` or `OLLAMA_PORT` in `.env`.

**Memory requirements:** Qwen2.5 3B needs at least 4 GB of memory, with 6–8 GB
recommended for responsive performance on personal computers. OpenVigie defaults
to a 2048-token context and one parallel inference to keep resource usage
predictable.

**How Vigi works:** Ollama does not browse the web. The OpenVigie collector
fetches attributed RSS/Atom news and primary security sources, then Vigi
(Qwen2.5 3B) analyzes and answers questions about those items locally, without
sending data to cloud AI services. Vigi can cross-reference the bulletin with
your declared asset inventory to identify relevant vulnerabilities.

The local chat endpoint is available at `/api/ai/chat`; Vigi is also accessible
as a floating chatbot in the web UI.

The Docker image copies the application into the container instead of mounting
the macOS project directory. This avoids intermittent file-sharing `EIO` errors
on Docker Desktop.

### With Node.js

Requirements:

- Node.js 22.13 or newer
- pnpm

```bash
cd apps/web
pnpm install
pnpm dev
```

Then open `http://localhost:3000`.

## Safety and responsible use

OpenVigie is intended for defensive monitoring, education, remediation, and
authorized security validation. Do not use information referenced by the
project against systems you do not own or have explicit permission to test.

Please report security issues privately as described in
[SECURITY.md](SECURITY.md).

## Contributing

Contributions are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) before opening
a pull request.

## License

OpenVigie is licensed under the GNU Affero General Public License v3.0. You may
use, study, modify, and redistribute it under the terms of that license. Modified
versions made available to users over a network must provide the corresponding
source code as required by the AGPL.

See [LICENSE](LICENSE) for the complete terms.

## Acknowledgements

OpenVigie was initiated by Swapshadow. The initial product concept and prototype
were developed collaboratively with OpenAI Codex.
