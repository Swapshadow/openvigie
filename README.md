# OpenVigie

OpenVigie is an open-source, asset-centric cybersecurity and vulnerability
intelligence platform.

Instead of showing another endless CVE feed, OpenVigie starts with the products
and versions that make up an infrastructure. It then correlates vendor
advisories, public vulnerability databases, exploitation signals, defensive
detection templates, and remediation guidance.

> **Project status:** early prototype. The interface currently uses
> demonstration data and must not be treated as a production vulnerability
> assessment.

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

The web prototype includes three editorial rhythms:

- a **daily** front page for new facts and immediate operational consequences;
- a **weekly** synthesis connecting technical and geopolitical signals;
- a **monthly** strategic dossier covering sovereignty, surveillance, platform
  power, cyber conflict, and crypto-enabled crime.

Each story exposes its sources and separates verified facts, contested or
developing information, and editorial analysis. See
[EDITORIAL_POLICY.md](EDITORIAL_POLICY.md).

## Planned sources

- CERT-FR
- NVD and CVE records
- CISA Known Exploited Vulnerabilities
- FIRST EPSS
- Vendor PSIRT advisories
- Exploit-DB / SearchSploit metadata
- Metasploit module metadata
- Nuclei template metadata

## Repository layout

```text
openvigie/
└── apps/
    └── web/        Miami-inspired web interface and first product prototype
```

## Run the web prototype

### With Docker Desktop

From the repository root:

```bash
docker compose up --build
```

Then open `http://localhost:3000`. Stop the application with `Ctrl+C`, or run
`docker compose down` from another terminal.

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
