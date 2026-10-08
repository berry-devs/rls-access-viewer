# Contributing to rls-access-viewer

## Development

Use the Node.js version in `.tool-versions` and pnpm 11 (pinned by `packageManager`; Corepack provides it). Users only
need Node.js >= 22 (`engines`).

This repository is a standalone pnpm root; its `pnpm-workspace.yaml` sets `minimumReleaseAge: 10080` (versions
published less than 7 days ago are refused) and disables dependency install scripts.

```bash
pnpm install
pnpm typecheck
pnpm lint               # ESLint (lint:fix applies auto-fixes)
pnpm format:check       # Prettier check (format rewrites files; Markdown is excluded)
pnpm build
pnpm test               # unit tests (fixtures, no database)
pnpm test:integration   # uses DATABASE_URL from your environment; skipped without it
```

> **Warning:** **Run the integration suite only against a disposable local database.** It executes
> `DROP SCHEMA IF EXISTS "RlsAccessViewerMixedCase" CASCADE` and `CREATE SCHEMA` on the database named by
> `DATABASE_URL`. The suite fails before connecting when `DATABASE_URL` points at a non-loopback host, but a local
> database still receives the DDL. `RLS_ACCESS_VIEWER_SCHEMA` selects the schema to extract (default `public`).

Runtime dependency: `pg` only. Source layout: `src/extract` (catalog queries → `rules.json`), `src/model`
(types, composition, redaction, config), `src/render` (HTML, SQL splitter / highlighter), `src/cli.ts` (the only
build entry; the package exposes the `rls-access-viewer` binary and nothing else).

CI (`.github/workflows/ci.yml`) runs ESLint, Prettier, typecheck, build and the unit tests on every pull request and on
pushes to `main`, and runs the unit tests and the packed CLI (installed with npm) on Node.js 22.0.0, the latest 22, 24
and 26. The integration suite runs in a separate workflow (`.github/workflows/integration.yml`) against a disposable
local Supabase stack started on the runner, with the fixture in `test/integration/fixtures/ci.sql`. It runs on pull
requests and pushes to `main` (except changes to Markdown files or `LICENSE` only), and on manual dispatch; it is not a
required check.

## Releasing

Publishing a GitHub Release runs `.github/workflows/release.yml`. A `build` job checks the Release, runs ESLint,
typecheck and the unit tests, builds from a clean `dist` and packs the tarball. A separate `publish` job, which only
has the OIDC token and installs no project dependencies, waits for approval on the `npm` environment and publishes
that tarball (so `prepublishOnly` does not run) to npm with trusted publishing (OIDC, with provenance; no npm token is
stored in the repository).

The release tag must be `v<version>` matching `version` in `package.json`, and the Release must be marked as a
pre-release exactly when the version contains `-`; otherwise the `build` job fails before anything is published.
Pre-release versions are published under the `next` dist-tag, others under `latest`. If that version is already on
npm (e.g. published by hand), the publish step is skipped and the job still succeeds.

Runs for different tags are not serialized, so when several Releases are waiting for approval, approve them from the
oldest version to the newest: an older version published after a newer one under `latest` moves `latest` back.

## Security

Report vulnerabilities privately as described in [SECURITY.md](SECURITY.md), not in public issues.
