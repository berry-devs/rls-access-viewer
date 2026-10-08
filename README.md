# rls-access-viewer

[![npm](https://img.shields.io/npm/v/@berry-devs/rls-access-viewer)](https://www.npmjs.com/package/@berry-devs/rls-access-viewer)
[![CI](https://github.com/berry-devs/rls-access-viewer/actions/workflows/ci.yml/badge.svg)](https://github.com/berry-devs/rls-access-viewer/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/berry-devs/rls-access-viewer/blob/main/LICENSE)

A **read-only viewer** for the access rules of a Supabase database. It reads the catalog of a local or remote
Supabase database and shows — for each table and operation — the RLS policies, GRANTs, function execute privileges,
Storage policies and the order in which they are evaluated, as a single-file HTML page organised as a
**table × operation (SELECT / INSERT / UPDATE / DELETE)** matrix. Supabase Storage is covered too: bucket settings and
the `storage.objects` rules, organised as a **bucket × operation** matrix.

It shows what the catalog says; it does not validate, test or simulate your policies, and it does not judge whether
they are correct. It runs on its own: no LLM or network service is involved. It focuses on making the SQL conditions
easy to read and does not write natural-language summaries.

> **Unofficial.** This is an independent tool and is not affiliated with, endorsed by or sponsored by Supabase.
> "Supabase" and "PostgreSQL" are used only to describe what the tool reads.

![The viewer: the table × operation matrix and the details of one cell, for a sample schema](https://raw.githubusercontent.com/berry-devs/rls-access-viewer/main/docs/images/viewer.png)

```
pg_catalog ──extract──▶ rules.json ──render──▶ index.html
```

## Quick start

In your Supabase project directory, with the local stack running (`supabase start`):

```bash
npx @berry-devs/rls-access-viewer generate --from-supabase-status
# or: pnpm dlx @berry-devs/rls-access-viewer … / yarn dlx @berry-devs/rls-access-viewer … (Yarn 2+) / bunx @berry-devs/rls-access-viewer …
```

Then open `out/index.html` in a browser.

To keep it in the project instead, install it as a dev dependency:

```bash
npm install -D @berry-devs/rls-access-viewer
# or: pnpm add -D @berry-devs/rls-access-viewer / yarn add -D @berry-devs/rls-access-viewer / bun add -D @berry-devs/rls-access-viewer
```

This is a command-line tool only. It has no library entry point, and importing it from code is not supported.

## Requirements

- Node.js >= 22
- A Supabase database to read from: a local Supabase stack (`supabase start`) or a remote Supabase project
- For `--from-supabase-status`: the Supabase CLI, installed in the project (`node_modules/.bin`) or on `PATH`

## Usage

The examples below write `rls-access-viewer <command>`. Run them as `npx @berry-devs/rls-access-viewer <command>`.
If you installed it in the project, you can run the local binary with `npm exec --no -- rls-access-viewer <command>`
(or `pnpm exec rls-access-viewer <command>`). Avoid a bare `npx rls-access-viewer`: where the package is not installed,
it would fetch an unrelated unscoped package of that name.

Run it from your Supabase project directory (the one containing `supabase/config.toml`):

```bash
# Local Supabase (recommended): take DB_URL from `supabase status -o env` (the port is not assumed)
rls-access-viewer generate --from-supabase-status

# The two stages separately
rls-access-viewer extract --from-supabase-status --out out/rules.json
rls-access-viewer render --in out/rules.json --out out/index.html
```

For a remote Supabase project, see [Connecting to a remote Supabase project](#connecting-to-a-remote-supabase-project).

Open `out/index.html` in a browser. Paths are resolved against the current directory.

| Command    | What it does                                             |
| ---------- | -------------------------------------------------------- |
| `extract`  | Query the catalogs and write `rules.json`                |
| `render`   | Generate the single-file HTML viewer from `rules.json`   |
| `generate` | `extract` followed by `render` (writes both to `--out-dir`) |

| Option                   | Description                                                                 |
| ------------------------ | --------------------------------------------------------------------------- |
| `--db-url-file <path>`   | Read the connection string from a file (keep it `chmod 600`). Highest precedence, like `--db-url`; the two cannot be combined |
| `--db-url <url>`         | Connection string. Highest precedence. Putting a password in it is **deprecated**: it remains in shell history and `ps` (a warning is printed) |
| `DATABASE_URL` (env)     | Used when neither `--db-url` nor `--db-url-file` is given                   |
| `--from-supabase-status` | Used last: runs `supabase status -o env` and keeps only the `DB_URL` line   |
| `--project-dir <dir>`    | Where `supabase/config.toml` lives (default: searched upward from the cwd)  |
| `--allow-remote`         | Allow non-loopback hosts (refused by default)                               |
| `--schema <name>`        | Target schema (default: `public`). Storage (`storage.objects` / `storage.buckets`) is always extracted as well |
| `--out <file>`           | `extract`: the `rules.json` path (default: `out/rules.json`); `render`: the HTML path (default: `out/index.html`) |
| `--in <file>`            | `render`: the input `rules.json` (default: `out/rules.json`)                |
| `--out-dir <dir>`        | `generate`: the directory for both files (default: `out`)                   |
| `--config <file>`        | Pattern tag config (default: the bundled `rls-access-viewer.config.json`)    |

Exit codes: `0` success, `1` usage / config / input error, `2` connection or catalog query failure
(an unreachable database always fails with a non-zero code).

## Connecting to a remote Supabase project

Locally, `--from-supabase-status` takes the connection string from the Supabase CLI, so nothing secret is typed.

For a remote project, use its session pooler connection string (a `postgresql://` URL). Copy the host from the
project's Connect dialog; the user name is `<role>.<ref>`. The direct connection (`db.<ref>.supabase.co`) is reachable
over IPv6 only unless the project has the IPv4 add-on. Hosts other than `localhost` / `127.0.0.0/8` / `::1` / UNIX
sockets are refused unless you pass `--allow-remote`. Keep the password off the command line, where it remains in shell
history and process listings (`ps`): leave it out of the URL and let the PostgreSQL client read it from `PGPASSWORD` or
`~/.pgpass`, or put the whole URL in a file only you can read and pass `--db-url-file`. The tool prints a warning when
`--db-url` contains a password. `DATABASE_URL` is accepted too; set it without typing the value on a command line.

Supabase signs its server certificates with its own root CA, which Node.js does not trust by default. Download the CA
certificate from the dashboard (Database settings > SSL Configuration) and pass its path with
`sslmode=verify-full&sslrootcert=<path>`. A relative path is resolved from the current directory, and unlike `psql`,
`~/.postgresql/root.crt` is not read automatically. `sslmode=require` / `prefer` do not skip verification here: the
PostgreSQL client used by the tool (node-postgres 8) treats them as `verify-full` and prints a warning, so without the
CA the connection fails with `SELF_SIGNED_CERT_IN_CHAIN`.

```bash
read -rs PGPASSWORD && export PGPASSWORD   # prompts without echo; nothing is written to history
rls-access-viewer generate --allow-remote --db-url "postgresql://rls_access_viewer.<ref>@aws-<N>-<region>.pooler.supabase.com:5432/postgres?sslmode=verify-full&sslrootcert=<path/to/prod-ca-2021.crt>"
```

> **Warning:** **Use a dedicated read-only role for remote databases**, not `postgres` or `service_role` credentials.
> The tool only reads system catalogs, which PostgreSQL lets every role read, so a role with nothing but `CONNECT` is
> enough.

## Security properties

- **Read-only.** Only the system catalogs are queried, inside a `READ ONLY` transaction. Table rows are never read,
  except the settings of `storage.buckets`. `--from-supabase-status` uses only the `DB_URL` line, and connection
  strings are never printed in errors.
- **Self-contained HTML.** The viewer is a single file that loads nothing external. Keys in recognized formats (e.g.
  JWTs and `sb_secret_…` keys) found anywhere in the catalog, such as function bodies or trigger arguments written by
  Database Webhooks, are replaced with `[REDACTED]` in `rules.json`, the HTML and log output; other secrets are not, so
  review the output before sharing it.

## Reading the viewer

**Tables × operations** has one row per table. A cell summarises what applies to `authenticated`:
`P n` / `R n` = PERMISSIVE / RESTRICTIVE policy counts, `deny` = no PERMISSIVE policy (denied by default),
`ALL` = includes a `FOR ALL` policy, `B n` / `A n` = BEFORE / AFTER triggers, `↯ n` = tables reached through
foreign key actions, `anon` = anon is allowed too. Tables with RLS disabled are highlighted in red.
Click a cell to open its details:

- **Policies**: roles, PERMISSIVE / RESTRICTIVE, USING and WITH CHECK; `FOR ALL` policies are expanded into all four
  operations and marked *from ALL*.
- **Effective rule per role**: PERMISSIVE policies combined with OR, then RESTRICTIVE ones with AND.
- **Evaluation order**: GRANT → USING → BEFORE triggers → WITH CHECK → constraints → foreign key actions →
  AFTER triggers.
- **GRANTs**: only differences from the Supabase default are highlighted.

The other tabs:

- **Functions (RPC)**: every function, flagging SECURITY DEFINER functions without a pinned `search_path` or
  executable by `anon`.
- **Views**: whether each view has `security_invoker` (and so follows the base tables' RLS).
- **Storage**: bucket settings and a **bucket × operation** matrix of the `storage.objects` policies. A policy is
  assigned to the buckets its `bucket_id` conditions name; one without a bucket condition appears in every bucket.
  Public buckets are flagged. When the extracting role cannot read `storage.buckets` (e.g. a role with nothing but
  `CONNECT`), the bucket settings are shown as unknown and only the buckets named by policies are listed.
- **Excluded & reference**: what was left out (extension-owned objects, platform event triggers), the roles,
  user-defined event triggers, foreign keys from other schemas, and what the tool does not cover.

## Trigger function analysis

For each trigger (and each function called from a policy, and each function in *Functions (RPC)*), the viewer shows
rules read from the PL/pgSQL body, next to the full definition:

- **Guards**: `IF <condition> THEN ... RAISE EXCEPTION` as *condition → error*.
- **Returns early**: conditional `RETURN`s that skip the rules below.
- **Side effects**: tables written with `INSERT` / `UPDATE` / `DELETE` / `MERGE` / `TRUNCATE`, and `PERFORM`ed
  functions.
- **Referenced columns**: `NEW.*` / `OLD.*`, and the columns compared between them.
- **Called functions**: the same analysis for the functions it calls, followed transitively.

The analysis is a deterministic reading of the body, not a PL/pgSQL parser; the full definition is authoritative.
Dynamic SQL run with `EXECUTE` is not analyzed.

## Pattern tags

Short tags are attached to conditions whose SQL matches a regular expression, e.g. `auth.uid()` → *own rows*.
Tags are plain pattern matches, not semantics: the default *own rows* tag also appears on a check such as
`(SELECT auth.uid()) IS NULL`.
The bundled defaults in [`rls-access-viewer.config.json`](https://github.com/berry-devs/rls-access-viewer/blob/main/rls-access-viewer.config.json) cover generic Supabase
patterns. Supply your own with `--config` (the file replaces the defaults; schema:
[`schemas/rls-access-viewer.config.schema.json`](https://github.com/berry-devs/rls-access-viewer/blob/main/schemas/rls-access-viewer.config.schema.json)):

```json
{
  "tags": [
    { "id": "self", "label": "own rows", "pattern": "\\bauth\\.uid\\s*\\(\\s*\\)", "description": "Compares with auth.uid()" }
  ]
}
```

Project-specific tags (for your own helper functions, or labels in another language) belong in a file kept in your
repository. Since it replaces the defaults, copy the bundled tags you want to keep into it:

```bash
rls-access-viewer generate --from-supabase-status --config ./rls-access-viewer.config.json
```

## rules.json

The intermediate file is described by [`schemas/rules.schema.json`](https://github.com/berry-devs/rls-access-viewer/blob/main/schemas/rules.schema.json). It holds catalog facts
(tables, columns, policies, triggers, constraints, grants, views, functions, excluded objects, and under `storage` the
bucket settings and the rules of `storage.objects`) plus the optional
`functions[].analysis` described above (computed at render time when absent, e.g. in files from older versions); the
matrix composition happens at render time, so `rules.json` can be diffed between two databases or commits.

## Limitations

- The `cron` schema is not covered. Of the storage schema only `storage.objects` and the settings of
  `storage.buckets` are covered; the rules of storage-schema functions called by triggers are not analyzed.
- Policy conditions are split into lines for display by a small purpose-built parser for `pg_get_expr` output, not a
  general SQL parser; expressions it cannot handle are shown as the original SQL.
- No natural-language summaries.
- The tool targets Supabase databases. The matrix summary and per-role panels assume Supabase's `anon` /
  `authenticated` / `service_role` roles; other PostgreSQL databases are not a supported target.

## Changelog

Release notes are published on [GitHub Releases](https://github.com/berry-devs/rls-access-viewer/releases).

## Contributing

See [CONTRIBUTING.md](https://github.com/berry-devs/rls-access-viewer/blob/main/CONTRIBUTING.md) for the development
setup, tests and CI. To report a vulnerability, see
[SECURITY.md](https://github.com/berry-devs/rls-access-viewer/blob/main/SECURITY.md).

## License

Copyright © 2026 Berry, Inc. Released under the MIT License — see
[LICENSE](https://github.com/berry-devs/rls-access-viewer/blob/main/LICENSE).
