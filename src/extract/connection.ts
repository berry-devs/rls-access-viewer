import { spawnSync } from "node:child_process";
import { existsSync, readFileSync, statSync } from "node:fs";
import { dirname, join, resolve } from "node:path";

export class ConnectionConfigError extends Error {}

export interface ResolveDbUrlOptions {
  dbUrl?: string;
  /** File holding the connection string, so that the password stays out of shell history and `ps`. */
  dbUrlFile?: string;
  env?: NodeJS.ProcessEnv;
  fromSupabaseStatus?: boolean;
  projectDir?: string;
  allowRemote?: boolean;
  /** Receives warnings (never containing the connection string). */
  warn?: (message: string) => void;
  /** Test seam. */
  runSupabaseStatus?: (projectDir: string) => string;
}

export const DB_URL_PASSWORD_WARNING =
  "Warning: --db-url contains a password, which can remain in shell history and process listings. " +
  "Prefer --db-url-file, PGPASSWORD / ~/.pgpass, DATABASE_URL from your environment, or --from-supabase-status.";

/**
 * Connection string precedence: --db-url or --db-url-file → DATABASE_URL → DB_URL from `supabase status -o env`.
 * .env files are never read: they commonly hold SERVICE_ROLE_KEY and other secrets next to the URL.
 */
export function resolveDbUrl(options: ResolveDbUrlOptions): string {
  const env = options.env ?? process.env;
  if (options.dbUrl && options.dbUrlFile) {
    throw new ConnectionConfigError("--db-url and --db-url-file cannot be used together");
  }
  const fromArgument = options.dbUrl?.trim() ?? "";
  if (fromArgument && hasPassword(fromArgument)) options.warn?.(DB_URL_PASSWORD_WARNING);
  let url =
    fromArgument ||
    (options.dbUrlFile ? readDbUrlFile(options.dbUrlFile, options.warn) : "") ||
    env.DATABASE_URL?.trim() ||
    "";
  if (!url && options.fromSupabaseStatus) {
    let projectDir: string | null;
    if (options.projectDir) {
      projectDir = resolve(options.projectDir);
      // Checked before spawning: a missing cwd makes spawnSync fail with ENOENT, which reads as a missing CLI.
      // An explicit --project-dir is not searched upward: README and --help describe it as where config.toml lives
      if (!existsSync(join(projectDir, "supabase", "config.toml"))) {
        throw new ConnectionConfigError(`supabase/config.toml not found in --project-dir: ${projectDir}`);
      }
    } else {
      projectDir = findSupabaseProjectDir(process.cwd());
      if (!projectDir) {
        throw new ConnectionConfigError(
          "supabase/config.toml not found. Point --project-dir at the Supabase project root"
        );
      }
    }
    const output = (options.runSupabaseStatus ?? runSupabaseStatus)(projectDir);
    url = pickDbUrlFromStatusEnv(output) ?? "";
    if (!url) {
      throw new ConnectionConfigError(
        "`supabase status -o env` printed no DB_URL (is the local Supabase stack running?)"
      );
    }
  }
  if (!url) {
    throw new ConnectionConfigError(
      "No database to connect to. Pass --db-url-file or --db-url, set DATABASE_URL, or use --from-supabase-status"
    );
  }
  assertAllowedHost(url, options.allowRemote ?? false, env);
  return url;
}

function hasPassword(url: string): boolean {
  try {
    const u = new URL(url);
    // pg-connection-string copies every query parameter into the config, so ?password= is a password too
    return u.password !== "" || (u.searchParams.get("password") ?? "") !== "";
  } catch {
    return false; // an unparsable URL is rejected later by assertAllowedHost
  }
}

/**
 * Reads a connection string from a file (surrounding whitespace removed). Errors name the path but never
 * include the file's contents.
 */
export function readDbUrlFile(path: string, warn?: (message: string) => void): string {
  let mode: number;
  try {
    const st = statSync(path);
    if (!st.isFile()) throw new ConnectionConfigError(`--db-url-file is not a regular file: ${path}`);
    mode = st.mode;
  } catch (e) {
    if (e instanceof ConnectionConfigError) throw e;
    throw new ConnectionConfigError(`--db-url-file does not exist or cannot be accessed: ${path}`);
  }
  let text: string;
  try {
    text = readFileSync(path, "utf8");
  } catch {
    throw new ConnectionConfigError(`--db-url-file cannot be read: ${path}`);
  }
  const url = text.trim();
  if (!url) throw new ConnectionConfigError(`--db-url-file is empty: ${path}`);
  // Windows reports synthetic permission bits, so the check only means something on POSIX
  if (process.platform !== "win32" && (mode & 0o077) !== 0) {
    warn?.(`Warning: ${path} is readable or writable by group or others; consider chmod 600 ${path}`);
  }
  return url;
}

/**
 * Picks only the DB_URL line from `supabase status -o env`.
 * The other lines (SERVICE_ROLE_KEY, JWT_SECRET, ...) are never returned or written anywhere.
 */
export function pickDbUrlFromStatusEnv(output: string): string | null {
  for (const line of output.split(/\r?\n/)) {
    const m = /^\s*DB_URL\s*=\s*(.*)$/.exec(line);
    if (!m) continue;
    let value = (m[1] ?? "").trim();
    if ((value.startsWith('"') && value.endsWith('"')) || (value.startsWith("'") && value.endsWith("'"))) {
      value = value.slice(1, -1);
    }
    return value || null;
  }
  return null;
}

export function findSupabaseProjectDir(start: string): string | null {
  let dir = resolve(start);
  for (;;) {
    if (existsSync(join(dir, "supabase", "config.toml"))) return dir;
    const parent = dirname(dir);
    if (parent === dir) return null;
    dir = parent;
  }
}

function runSupabaseStatus(projectDir: string): string {
  // The CLI is often installed only as a project devDependency, so look in node_modules/.bin before PATH
  const candidates = [join(projectDir, "node_modules", ".bin", "supabase"), "supabase"];
  for (const bin of candidates) {
    if (bin !== "supabase" && !existsSync(bin)) continue;
    const result = spawnSync(bin, ["status", "-o", "env"], {
      cwd: projectDir,
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
      timeout: 60_000
    });
    if (result.error && (result.error as NodeJS.ErrnoException).code === "ENOENT") continue;
    if (result.status !== 0) {
      throw new ConnectionConfigError(
        `\`supabase status -o env\` failed (exit code ${String(result.status)}). Check that the local Supabase stack is running`
      );
    }
    return result.stdout;
  }
  throw new ConnectionConfigError("supabase CLI not found");
}

const LOOPBACK_HOSTS = new Set(["localhost", "127.0.0.1", "::1", "[::1]"]);

export function isLoopbackHost(hostname: string): boolean {
  const h = hostname.toLowerCase();
  if (h === "") return true; // UNIX domain socket
  if (LOOPBACK_HOSTS.has(h)) return true;
  return /^127(?:\.\d{1,3}){3}$/.test(h);
}

function assertAllowedHost(url: string, allowRemote: boolean, env: NodeJS.ProcessEnv): void {
  // Evaluated even with --allow-remote, so that a malformed URL is still rejected
  const loopbackOnly = connectsOnlyToLoopback(url, env);
  if (!loopbackOnly && !allowRemote) {
    throw new ConnectionConfigError(
      "Connections to non-loopback hosts are refused by default. Pass --allow-remote if this host is intended"
    );
  }
}

/**
 * Whether every host pg would connect to for this URL is loopback or a UNIX socket, following ?host= and the
 * PGHOST fallback. Throws ConnectionConfigError (without the URL) when it is not a postgresql:// URL.
 */
export function connectsOnlyToLoopback(url: string, env: NodeJS.ProcessEnv): boolean {
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    // Never echo the connection string in the message
    throw new ConnectionConfigError("The connection string is not a URL (use the postgresql://... form)");
  }
  if (!/^postgres(ql)?:$/.test(parsed.protocol)) {
    throw new ConnectionConfigError("The connection string must start with postgresql:// or postgres://");
  }
  const hostParam = parsed.searchParams.get("host");
  let hosts = hostParam && !hostParam.startsWith("/") ? [hostParam] : [parsed.hostname];
  // pg falls back to PGHOST when the URL has no host, so an empty host is only a local socket if PGHOST agrees
  const pgHost = env.PGHOST?.trim();
  if (!hostParam && parsed.hostname === "" && pgHost) {
    hosts = pgHost.split(",").map((h) => (h.trim().startsWith("/") ? "" : h.trim()));
  }
  return hosts.every(isLoopbackHost);
}
