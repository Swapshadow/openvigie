# Contributing to OpenVigie

Thank you for helping make vulnerability intelligence more accessible and
actionable.

## Before contributing

1. Search existing issues and pull requests.
2. Open a discussion or issue for substantial product or architecture changes.
3. Never include credentials, private customer data, proprietary advisories, or
   unredacted infrastructure details.
4. Do not submit weaponized payloads or features that execute exploits.

## Development

The current application lives in `apps/web`.

```bash
cd apps/web
pnpm install
pnpm dev
```

Before submitting a pull request:

```bash
pnpm lint
pnpm build
```

## Data-source contributions

A connector should:

- identify its upstream source and applicable terms;
- preserve source URLs and publication timestamps;
- normalize data without removing the original evidence;
- document rate limits and authentication requirements;
- fail safely when data is incomplete;
- include fixtures and matching tests before being enabled by default.

## Pull requests

Keep pull requests focused. Explain the problem, the chosen approach, validation
performed, and any security or data-quality trade-offs.

By contributing, you agree that your contribution is licensed under the
project's AGPL-3.0 license.
