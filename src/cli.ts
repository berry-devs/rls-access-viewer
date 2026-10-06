#!/usr/bin/env node
import { mkdirSync, readFileSync, realpathSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { parseArgs } from "node:util";
import { ConnectionConfigError, resolveDbUrl } from "./extract/connection.ts";
import { DbConnectionError, extractRules } from "./extract/index.ts";
import { compileTags, ConfigError, loadConfig } from "./model/config.ts";
import { redactDeep, redactString } from "./model/redact.ts";
import { assertRulesDocument, RulesDocumentError } from "./model/validate.ts";
import type { RulesDocument } from "./model/types.ts";
import { renderHtml } from "./render/html.ts";

export const EXIT_OK = 0;
export const EXIT_USAGE = 1;
export const EXIT_DB = 2;

const USAGE = `Usage: rls-access-viewer <command> [options]

Commands:
  extract    Query the database catalogs and write rules.json
  render     Generate the single-file HTML viewer from rules.json
  generate   Run extract and then render

Connection (extract / generate). Precedence: --db-url or --db-url-file, then DATABASE_URL, then --from-supabase-status
  --db-url-file <path>      Read the connection string from a file (chmod 600); keeps it out of history and ps
  --db-url <url>            Connection string (postgresql://...) of a local or remote Supabase database.
                            Do not put a password in it (it remains in shell history and ps): use PGPASSWORD,
                            ~/.pgpass or --db-url-file instead
  --from-supabase-status    Use DB_URL from \`supabase status -o env\` (all other lines are discarded)
  --project-dir <dir>       Directory containing supabase/config.toml (default: search upward)
  --allow-remote            Allow non-loopback hosts (refused by default)
  --schema <name>           Target schema (default: public)

Input / output:
  --out <file>              extract: rules.json path (default: out/rules.json)
                            render:  HTML path (default: out/index.html)
  --in <file>               render:  input rules.json (default: out/rules.json)
  --out-dir <dir>           generate: output directory (default: out)
  --config <file>           Pattern tag config (default: the bundled rls-access-viewer.config.json)
  -h, --help                Show this help
`;

const OPTIONS = {
  "db-url": { type: "string" },
  "db-url-file": { type: "string" },
  "from-supabase-status": { type: "boolean" },
  "project-dir": { type: "string" },
  "allow-remote": { type: "boolean" },
  schema: { type: "string" },
  out: { type: "string" },
  in: { type: "string" },
  "out-dir": { type: "string" },
  config: { type: "string" },
  help: { type: "boolean", short: "h" }
} as const;

export interface CliIo {
  stdout: (s: string) => void;
  stderr: (s: string) => void;
  env: NodeJS.ProcessEnv;
  cwd: string;
}

const defaultIo: CliIo = {
  stdout: (s) => process.stdout.write(s),
  stderr: (s) => process.stderr.write(s),
  env: process.env,
  cwd: process.cwd()
};

class UsageError extends Error {}

export async function main(argv: string[], io: CliIo = defaultIo): Promise<number> {
  // Redact log lines too, in case an error message carries a connection string
  const log = (s: string) => io.stderr(`${redactString(s)}\n`);
  try {
    const { values, positionals } = parseArgs({ args: argv, options: OPTIONS, allowPositionals: true, strict: true });
    const command = positionals[0];
    if (values.help || !command) {
      io.stdout(USAGE);
      return values.help ? EXIT_OK : EXIT_USAGE;
    }
    if (positionals.length > 1) throw new UsageError(`Unexpected arguments: ${positionals.slice(1).join(" ")}`);
    const abs = (p: string) => resolve(io.cwd, p);
    if (values["db-url"] !== undefined && values["db-url-file"] !== undefined) {
      throw new UsageError("--db-url and --db-url-file cannot be used together");
    }
    // An explicitly empty value must not silently fall back to DATABASE_URL, supabase status or the upward search
    for (const name of ["db-url", "db-url-file", "project-dir"] as const) {
      if (values[name] !== undefined && values[name].trim() === "") throw new UsageError(`--${name} must not be empty`);
    }

    const extract = async (outPath: string): Promise<RulesDocument> => {
      const connectionString = resolveDbUrl({
        dbUrl: values["db-url"],
        dbUrlFile: values["db-url-file"] !== undefined ? abs(values["db-url-file"]) : undefined,
        env: io.env,
        warn: log,
        fromSupabaseStatus: values["from-supabase-status"],
        projectDir: values["project-dir"] ? abs(values["project-dir"]) : undefined,
        allowRemote: values["allow-remote"]
      });
      const doc = await extractRules({ connectionString, schema: values.schema });
      writeFile(outPath, `${JSON.stringify(doc, null, 2)}\n`);
      log(`Wrote rules.json: ${outPath} (${doc.tables.length} tables, ${doc.functions.length} functions)`);
      return doc;
    };
    const render = (doc: RulesDocument, outPath: string) => {
      const tags = compileTags(loadConfig(values.config ? abs(values.config) : undefined));
      writeFile(outPath, renderHtml(doc, { tags }));
      log(`Wrote viewer: ${outPath}`);
    };

    switch (command) {
      case "extract":
        await extract(abs(values.out ?? "out/rules.json"));
        return EXIT_OK;
      case "render": {
        const inPath = abs(values.in ?? "out/rules.json");
        let parsed: unknown;
        try {
          parsed = JSON.parse(readFileSync(inPath, "utf8"));
        } catch {
          throw new RulesDocumentError(`Cannot read rules.json: ${inPath}`);
        }
        assertRulesDocument(parsed);
        render(redactDeep(parsed), abs(values.out ?? "out/index.html"));
        return EXIT_OK;
      }
      case "generate": {
        const dir = abs(values["out-dir"] ?? "out");
        const doc = await extract(join(dir, "rules.json"));
        render(doc, join(dir, "index.html"));
        return EXIT_OK;
      }
      default:
        throw new UsageError(`Unknown command: ${command}`);
    }
  } catch (e) {
    if (e instanceof DbConnectionError) {
      log(`Error: ${e.message}`);
      return EXIT_DB;
    }
    if (
      e instanceof UsageError ||
      e instanceof ConfigError ||
      e instanceof ConnectionConfigError ||
      e instanceof RulesDocumentError
    ) {
      log(`Error: ${e.message}`);
      return EXIT_USAGE;
    }
    if (e instanceof TypeError && (e as { code?: string }).code?.startsWith("ERR_PARSE_ARGS")) {
      log(`Error: ${e.message}\n\n${USAGE}`);
      return EXIT_USAGE;
    }
    log(`Unexpected error: ${e instanceof Error ? e.message : String(e)}`);
    return EXIT_USAGE;
  }
}

function writeFile(path: string, content: string): void {
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, content, "utf8");
}

// Do not run when imported by tests. The bin is invoked through a symlink, so compare real paths
const invokedDirectly = (() => {
  const entry = process.argv[1];
  if (!entry) return false;
  try {
    return realpathSync(entry) === realpathSync(fileURLToPath(import.meta.url));
  } catch {
    return false;
  }
})();

if (invokedDirectly) {
  main(process.argv.slice(2)).then((code) => {
    process.exitCode = code;
  });
}
