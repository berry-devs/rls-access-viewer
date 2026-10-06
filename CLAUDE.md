# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

`@berry-devs/rls-access-viewer` is a CLI-only tool (no library entry point) that reads the catalog of a Supabase
Postgres database and renders a single-file HTML viewer of RLS policies, GRANTs, function execute privileges, triggers /
FK actions and Storage policies, as a table × operation matrix in evaluation order. It is read-only and describes what
the catalog says; it does not validate or simulate policies. README.md is the user-facing spec (it is also the npm
package page, so links in it are absolute GitHub URLs) — keep it in sync when behavior changes. Development and CI notes
live in CONTRIBUTING.md.

## Commands

Node.js >= 22 to run the CLI (`engines`); development uses the version in `.tool-versions` and pnpm 11 (pinned by
`packageManager`). Keep the code within Node.js 22 APIs: `@types/node` is pinned to 22.x so that `typecheck` rejects
APIs newer than the 22 line (APIs added during 22.x still pass it; the 22.0.0 `node-compat` CI job checks the lower
bound).

```bash
pnpm install
pnpm typecheck              # tsc --noEmit (tsconfig include: src/, test/, docs/, tsup.config.ts)
pnpm lint                   # ESLint over the whole repository except dist/ and out/; lint:fix applies fixes
pnpm format:check           # Prettier check (printWidth 120, double quotes, no trailing commas; *.md excluded)
pnpm format                 # Prettier --write
pnpm build                  # tsup → dist/cli.js (the only entry)
pnpm test                   # unit tests: node --test over test/*.test.ts, fixtures only, no DB
pnpm test:integration       # test/integration/*.test.ts against DATABASE_URL; skipped when unset
pnpm dev -- generate --from-supabase-status   # run from source via tsx
pnpm pack --dry-run         # check what gets published (`files` in package.json)
```

Run a single test file / test by name:

```bash
node --import tsx --test test/plpgsql.test.ts
node --import tsx --test --test-name-pattern="guards" test/plpgsql.test.ts
```

**The integration suite runs `DROP SCHEMA IF EXISTS "RlsAccessViewerMixedCase" CASCADE` / `CREATE SCHEMA` on the
database in `DATABASE_URL`** — only point it at a disposable local DB. It fails before connecting when the URL is
not loopback (`connectsOnlyToLoopback`, shared with the CLI). `RLS_ACCESS_VIEWER_SCHEMA` selects the schema to
extract (default `public`).

CI (`.github/workflows/ci.yml`) runs `lint` / `format:check` / `typecheck` / `build` / `test` (not `test:integration`);
run the same before pushing. Its `node-compat` matrix (Node.js 22.0.0 / 22 / 24 / 26: unit tests, and the packed tarball
installed with npm and run) only runs in CI. `.github/workflows/integration.yml` runs `test:integration` against a
disposable local Supabase stack with `test/integration/fixtures/ci.sql`, on pull requests and pushes to `main` that
change more than Markdown files or `LICENSE`, and on manual dispatch (not a required check).

`pnpm-workspace.yaml` makes this a standalone pnpm root with `minimumReleaseAge: 10080` (packages newer than 7 days
are refused) and dependency install scripts disabled; keep these when touching dependencies. The only runtime
dependency is `pg`; avoid adding others (e.g. `src/model/schema.ts` is a hand-written JSON Schema checker precisely
to avoid a validator dependency).

## Architecture

Pipeline: `pg_catalog ──extract──▶ rules.json ──render──▶ index.html`. `src/cli.ts` exposes `extract`, `render`
and `generate` (both) and maps errors to exit codes (0 ok, 1 usage/config/input, 2 connection/catalog query).

- **`src/extract/`** — `connection.ts` resolves the DB URL (precedence: `--db-url` / `--db-url-file`, then
  `DATABASE_URL`, then `--from-supabase-status`, which keeps only the `DB_URL` line), refuses non-loopback hosts
  without `--allow-remote`, and never prints the connection string. `queries.ts` holds the catalog SQL; `index.ts` runs it
  in a `READ ONLY` transaction and turns raw rows into a `RulesDocument` (`assembleDocument` / `assembleStorage` are
  pure and unit-tested from fixtures). Storage (`storage.objects` policies + `storage.buckets` settings) is always
  extracted regardless of `--schema`, and must degrade gracefully when the role cannot read `storage.buckets`.
- **`rules.json`** — catalog facts only, typed in `src/model/types.ts` (`FORMAT_VERSION`) and described by
  `schemas/rules.schema.json`. The TS types and the JSON Schema must change together; `validate.ts` checks input
  to `render` against the schema. New fields are added as optional so older `rules.json` files stay valid.
  Matrix composition is deliberately **not** stored — it happens at render time so `rules.json` diffs cleanly.
- **`src/model/`** — render-time logic: `cells.ts` (FOR ALL expansion, PERMISSIVE OR / RESTRICTIVE AND per role,
  triggers per event, transitive FK cascade effects, GRANT diffs against Supabase defaults), `storage.ts` (assigning
  `storage.objects` policies to buckets from `bucket_id` conditions), `plpgsql.ts` (a purpose-built, deterministic
  reader of function bodies — guards, early returns, side effects, NEW/OLD columns, call graph with
  `MAX_CALL_DEPTH` — not a full parser; it masks comments/strings first), `redact.ts` (secret redaction applied to
  rules.json, HTML and logs), `config.ts` (pattern tags from `rls-access-viewer.config.json`).
  `functions[].analysis` is computed at extract time but recomputed at render when absent.
- **`src/render/`** — `html.ts` builds the single-file page; `sql.ts` is the small top-level AND/OR splitter and
  highlighter for `pg_get_expr` output; `functionRules.ts` renders the PL/pgSQL analysis; `assets.ts` holds the
  inline `STYLE` / `SCRIPT`. The page carries a CSP that allows only those inline blocks **by sha256 hash** (computed
  from the constants), loads nothing external, escapes every name/definition, and escapes `<` in embedded JSON.
  Don't introduce inline event handlers, extra `<script>`/`<style>` blocks or external resources.

Runtime files resolved relative to the module (`schemas/`, the bundled config) must work from both `src/` (tsx) and
`dist/` (built), and must be listed in `package.json` `files`.

## Tests

Unit tests build `RulesDocument`s with helpers in `test/fixtures.ts` (`table`, `policy`, `trigger`,
`defaultGrants`, …) rather than a database. The integration test derives expected values from independent catalog
queries instead of hard-coding them.

`docs/screenshot/` builds the README screenshot from a fictional schema only, never a real project's data; the
regeneration steps are in the header comment of `generate.ts`.
