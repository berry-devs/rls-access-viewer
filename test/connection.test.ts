import assert from "node:assert/strict";
import { chmodSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { after, describe, it } from "node:test";
import pg from "pg";
import {
  ConnectionConfigError,
  connectsOnlyToLoopback,
  DB_URL_PASSWORD_WARNING,
  isLoopbackHost,
  pickDbUrlFromStatusEnv,
  resolveDbUrl
} from "../src/extract/connection.ts";
import { pgUrl } from "./fixtures.ts";

const LOCAL = pgUrl({ user: "postgres", password: "postgres", port: 55322 });
const STATUS_URL = pgUrl({ user: "a", password: "b", port: 54322 });

// Work under the git-ignored out/ directory
const outRoot = join(import.meta.dirname, "..", "out");
mkdirSync(outRoot, { recursive: true });
const work = mkdtempSync(join(outRoot, "test-connection-"));
after(() => rmSync(work, { recursive: true, force: true }));
// A Supabase project as far as resolveDbUrl is concerned: only supabase/config.toml has to exist
const PROJECT_DIR = join(work, "project");
mkdirSync(join(PROJECT_DIR, "supabase"), { recursive: true });
writeFileSync(join(PROJECT_DIR, "supabase", "config.toml"), 'project_id = "test"\n');

describe("resolveDbUrl", () => {
  it("prefers --db-url over DATABASE_URL", () => {
    assert.equal(
      resolveDbUrl({
        dbUrl: LOCAL,
        env: { DATABASE_URL: pgUrl({ user: "u", password: "p", host: "localhost", port: 1, db: "x" }) }
      }),
      LOCAL
    );
  });

  it("falls back to DATABASE_URL", () => {
    assert.equal(resolveDbUrl({ env: { DATABASE_URL: LOCAL } }), LOCAL);
  });

  it("falls back to DB_URL from supabase status (any port)", () => {
    const url = resolveDbUrl({
      env: {},
      fromSupabaseStatus: true,
      projectDir: PROJECT_DIR,
      runSupabaseStatus: (dir) => {
        assert.equal(dir, PROJECT_DIR);
        return `API_URL="http://127.0.0.1:55321"\nDB_URL="${LOCAL}"\nSERVICE_ROLE_KEY="eyJhbGciOiJIUzI1NiJ9.eyJyb2xlIjoic2VydmljZSJ9.sig"\n`;
      }
    });
    assert.equal(url, LOCAL);
  });

  it("fails without any connection target", () => {
    assert.throws(() => resolveDbUrl({ env: {} }), ConnectionConfigError);
  });

  it("refuses non-loopback hosts without --allow-remote and keeps the URL out of the message", () => {
    const remote = pgUrl({ user: "postgres", password: "supersecret", host: "db.example.com", port: 5432 });
    assert.throws(
      () => resolveDbUrl({ dbUrl: remote, env: {} }),
      (e: unknown) =>
        e instanceof ConnectionConfigError && !e.message.includes("supersecret") && !e.message.includes("example.com")
    );
    assert.equal(resolveDbUrl({ dbUrl: remote, env: {}, allowRemote: true }), remote);
  });

  it("applies the loopback check to a ?host= override", () => {
    assert.throws(
      () =>
        resolveDbUrl({
          dbUrl: pgUrl({ user: "u", password: "p", host: "localhost", db: "db", query: "host=10.0.0.5" }),
          env: {}
        }),
      ConnectionConfigError
    );
  });

  it("fails on a non-URL string without echoing it", () => {
    assert.throws(
      () => resolveDbUrl({ dbUrl: "host=db.example.com password=secret", env: {} }),
      (e: unknown) => e instanceof ConnectionConfigError && !e.message.includes("secret")
    );
  });

  it("still rejects a non-URL string with --allow-remote", () => {
    assert.throws(
      () => resolveDbUrl({ dbUrl: "host=db.example.com password=secret", env: {}, allowRemote: true }),
      (e: unknown) =>
        e instanceof ConnectionConfigError && !e.message.includes("secret") && !e.message.includes("example.com")
    );
  });
});

describe("--from-supabase-status with --project-dir", () => {
  /** Resolves with a stub that would succeed, so that only the config.toml check can make it throw. */
  const rejectsBeforeStatus = (projectDir: string) => {
    let called = false;
    assert.throws(
      () =>
        resolveDbUrl({
          env: {},
          fromSupabaseStatus: true,
          projectDir,
          runSupabaseStatus: () => {
            called = true;
            return `DB_URL="${LOCAL}"\n`;
          }
        }),
      (e: unknown) =>
        e instanceof ConnectionConfigError &&
        /supabase\/config\.toml not found/.test(e.message) &&
        e.message.includes(projectDir)
    );
    assert.equal(called, false);
  };

  it("rejects a directory that does not exist, naming the path, without running supabase status", () => {
    rejectsBeforeStatus(join(work, "no-such-project"));
  });

  it("rejects a directory without supabase/config.toml and does not search upward", () => {
    const app = join(PROJECT_DIR, "app"); // inside a project, so an upward search would find config.toml
    mkdirSync(app, { recursive: true });
    rejectsBeforeStatus(app);
  });

  it("rejects a path that is a file", () => {
    const file = join(work, "not-a-directory");
    writeFileSync(file, "");
    rejectsBeforeStatus(file);
  });
});

describe("resolveDbUrl with an empty URL host", () => {
  const EMPTY_HOST = "postgresql:///postgres";

  it("refuses an empty host when PGHOST points to a remote host", () => {
    assert.throws(
      () => resolveDbUrl({ dbUrl: EMPTY_HOST, env: { PGHOST: "remote.example.com" } }),
      ConnectionConfigError
    );
    assert.throws(
      () => resolveDbUrl({ dbUrl: EMPTY_HOST, env: { PGHOST: "localhost,remote.example.com" } }),
      ConnectionConfigError
    );
  });

  it("allows it with --allow-remote", () => {
    assert.equal(
      resolveDbUrl({ dbUrl: EMPTY_HOST, env: { PGHOST: "remote.example.com" }, allowRemote: true }),
      EMPTY_HOST
    );
  });

  it("allows an empty host without PGHOST, with a loopback PGHOST or with a socket directory", () => {
    assert.equal(resolveDbUrl({ dbUrl: EMPTY_HOST, env: {} }), EMPTY_HOST);
    assert.equal(resolveDbUrl({ dbUrl: EMPTY_HOST, env: { PGHOST: "localhost" } }), EMPTY_HOST);
    assert.equal(resolveDbUrl({ dbUrl: EMPTY_HOST, env: { PGHOST: "/var/run/postgresql" } }), EMPTY_HOST);
  });

  it("ignores PGHOST when the URL names a host", () => {
    assert.equal(resolveDbUrl({ dbUrl: LOCAL, env: { PGHOST: "remote.example.com" } }), LOCAL);
  });
});

describe("pickDbUrlFromStatusEnv", () => {
  it("returns only the DB_URL line, unquoted", () => {
    const out = `ANON_KEY="eyJx.eyJy.z"\nDB_URL="${STATUS_URL}"\nJWT_SECRET="super-secret-jwt"\n`;
    assert.equal(pickDbUrlFromStatusEnv(out), STATUS_URL);
  });

  it("returns null without DB_URL", () => {
    assert.equal(pickDbUrlFromStatusEnv("API_URL=http://x\n"), null);
  });
});

describe("isLoopbackHost", () => {
  it("allows localhost, 127.x, ::1 and sockets", () => {
    for (const h of ["localhost", "127.0.0.1", "127.1.2.3", "::1", "[::1]", ""])
      assert.equal(isLoopbackHost(h), true, h);
    for (const h of ["10.0.0.1", "db.example.com", "127.0.0.1.example.com"]) assert.equal(isLoopbackHost(h), false, h);
  });
});

describe("connectsOnlyToLoopback", () => {
  it("accepts loopback hosts, 127.x, IPv6 ::1 and UNIX sockets", () => {
    for (const url of [
      pgUrl({ user: "u", host: "localhost" }),
      pgUrl({ user: "u", host: "127.4.5.6" }),
      "postgresql://u@[::1]:5432/postgres",
      "postgresql:///postgres",
      "postgresql:///postgres?host=/var/run/postgresql"
    ])
      assert.equal(connectsOnlyToLoopback(url, {}), true, url);
  });

  it("rejects remote hosts, including through ?host= and PGHOST", () => {
    assert.equal(connectsOnlyToLoopback(pgUrl({ user: "u", host: "db.example.com" }), {}), false);
    assert.equal(connectsOnlyToLoopback("postgresql://u@[2001:db8::1]:5432/postgres", {}), false);
    assert.equal(connectsOnlyToLoopback(pgUrl({ user: "u", host: "localhost", query: "host=10.0.0.5" }), {}), false);
    assert.equal(connectsOnlyToLoopback("postgresql:///postgres", { PGHOST: "db.example.com" }), false);
    assert.equal(connectsOnlyToLoopback("postgresql:///postgres", { PGHOST: "localhost,db.example.com" }), false);
    assert.equal(connectsOnlyToLoopback("postgresql:///postgres", { PGHOST: "localhost,/tmp" }), true);
  });

  it("throws for a non-URL string without echoing it", () => {
    assert.throws(
      () => connectsOnlyToLoopback("host=db.example.com password=secret", {}),
      (e: unknown) => e instanceof ConnectionConfigError && !e.message.includes("secret")
    );
  });
});

describe("--db-url-file", () => {
  const dir = mkdtempSync(join(outRoot, "test-db-url-file-"));
  after(() => rmSync(dir, { recursive: true, force: true }));
  const SECRET_URL = pgUrl({ user: "svc", password: "file-secret-pw", port: 54322 });
  const file = (name: string, content: string, mode = 0o600) => {
    const path = join(dir, name);
    writeFileSync(path, content);
    chmodSync(path, mode);
    return path;
  };
  const resolveWith = (dbUrlFile: string, extra: Parameters<typeof resolveDbUrl>[0] = {}) => {
    const warnings: string[] = [];
    const url = resolveDbUrl({ dbUrlFile, env: {}, warn: (m) => warnings.push(m), ...extra });
    return { url, warnings };
  };
  const failsWithout = (fn: () => unknown, forbidden: string[]) =>
    assert.throws(
      fn,
      (e: unknown) => e instanceof ConnectionConfigError && forbidden.every((f) => !e.message.includes(f))
    );

  it("reads the connection string and trims surrounding whitespace and the trailing newline", () => {
    const { url, warnings } = resolveWith(file("ok.url", `  ${SECRET_URL}\n\n`));
    assert.equal(url, SECRET_URL);
    assert.deepEqual(warnings, []);
  });

  it("takes precedence over DATABASE_URL", () => {
    const { url } = resolveWith(file("prec.url", SECRET_URL), {
      env: { DATABASE_URL: "postgresql://other@localhost/x" }
    });
    assert.equal(url, SECRET_URL);
  });

  it("fails for an empty, missing or directory path without including file contents", () => {
    failsWithout(() => resolveWith(file("empty.url", " \n\t\n")), ["file-secret-pw"]);
    failsWithout(() => resolveWith(join(dir, "missing.url")), []);
    failsWithout(() => resolveWith(dir), []);
    assert.throws(() => resolveWith(join(dir, "missing.url")), /does not exist or cannot be accessed: .*missing\.url/);
    assert.throws(() => resolveWith(dir), /is not a regular file/);
    assert.throws(() => resolveWith(file("blank.url", "\n")), /is empty/);
  });

  it("keeps the contents out of the error when the URL in the file is rejected", () => {
    const remote = file("remote.url", pgUrl({ user: "svc", password: "file-secret-pw", host: "db.example.com" }));
    failsWithout(() => resolveWith(remote), ["file-secret-pw", "db.example.com", "postgresql://"]);
  });

  it("cannot be combined with --db-url", () => {
    assert.throws(
      () => resolveDbUrl({ dbUrl: LOCAL, dbUrlFile: file("both.url", SECRET_URL), env: {} }),
      /cannot be used together/
    );
  });

  it(
    "warns about group / other permissions on POSIX, but not for mode 0600",
    { skip: process.platform === "win32" },
    () => {
      const open = resolveWith(file("open.url", SECRET_URL, 0o644));
      assert.equal(open.url, SECRET_URL);
      assert.equal(open.warnings.length, 1);
      assert.match(open.warnings[0] ?? "", /consider chmod 600/);
      assert.ok(!open.warnings[0]?.includes("file-secret-pw"));
      assert.deepEqual(resolveWith(file("private.url", SECRET_URL, 0o600)).warnings, []);
    }
  );

  it("does not trigger the --db-url password warning", () => {
    assert.ok(!resolveWith(file("pw.url", SECRET_URL)).warnings.includes(DB_URL_PASSWORD_WARNING));
  });
});

describe("--db-url password warning", () => {
  const collect = (options: Parameters<typeof resolveDbUrl>[0]) => {
    const warnings: string[] = [];
    resolveDbUrl({ env: {}, ...options, warn: (m) => warnings.push(m) });
    return warnings;
  };

  it("warns once when --db-url carries a password, without echoing it", () => {
    const warnings = collect({ dbUrl: pgUrl({ user: "postgres", password: "arg-secret-pw", port: 54322 }) });
    assert.deepEqual(warnings, [DB_URL_PASSWORD_WARNING]);
    assert.ok(!warnings[0]?.includes("arg-secret-pw"));
    assert.ok(!warnings[0]?.includes("postgresql://"));
  });

  it("warns when the password is passed as a ?password= query parameter, without echoing it", () => {
    const warnings = collect({ dbUrl: "postgresql://u@127.0.0.1:54322/x?password=query-secret-pw" });
    assert.deepEqual(warnings, [DB_URL_PASSWORD_WARNING]);
    assert.ok(!warnings[0]?.includes("query-secret-pw"));
    assert.deepEqual(collect({ dbUrl: "postgresql://u@127.0.0.1:54322/x?sslmode=disable" }), []);
    assert.deepEqual(collect({ dbUrl: "postgresql://u@127.0.0.1:54322/x?password=" }), []);
  });

  it("does not warn for a URL without a password, DATABASE_URL or supabase status", () => {
    assert.deepEqual(collect({ dbUrl: "postgresql://postgres@127.0.0.1:54322/postgres" }), []);
    assert.deepEqual(
      collect({ env: { DATABASE_URL: pgUrl({ user: "postgres", password: "env-pw", port: 54322 }) } }),
      []
    );
    assert.deepEqual(
      collect({
        fromSupabaseStatus: true,
        projectDir: PROJECT_DIR,
        runSupabaseStatus: (dir) => {
          assert.equal(dir, PROJECT_DIR);
          return `DB_URL="${pgUrl({ user: "postgres", password: "status-pw", port: 54322 })}"\n`;
        }
      }),
      []
    );
  });

  it("accepts a password-less URL so that PGPASSWORD / ~/.pgpass can supply the password", () => {
    const url = "postgresql://postgres@127.0.0.1:54322/postgres";
    assert.equal(resolveDbUrl({ dbUrl: url, env: { PGPASSWORD: "from-env" } }), url);
  });
});

/** The postgresql:// URLs in the fenced code blocks of the README section on remote projects. */
function remoteExampleUrls(): string[] {
  const readme = readFileSync(join(import.meta.dirname, "..", "README.md"), "utf8");
  const start = readme.indexOf("\n## Connecting to a remote Supabase project");
  assert.ok(start >= 0, "README section not found");
  const end = readme.indexOf("\n## ", start + 1);
  const section = readme.slice(start, end < 0 ? undefined : end);
  const blocks = [...section.matchAll(/^```[^\n]*\n([\s\S]*?)^```/gm)].map((m) => m[1] ?? "");
  const urls = blocks.flatMap((block) => block.match(/postgresql:\/\/[^\s"'`]+/g) ?? []);
  assert.ok(urls.length > 0, "no example URL in the README section");
  return urls;
}

const DUMMY_CA = join(work, "dummy-ca.crt");
const DUMMY_PEM = "-----BEGIN CERTIFICATE-----\nnot a real certificate\n-----END CERTIFICATE-----\n";
writeFileSync(DUMMY_CA, DUMMY_PEM);

/** Replaces the README placeholders: the CA path with a dummy PEM, everything else with "x". */
function materialize(url: string): string {
  return url.replace(/sslrootcert=<[^>]*>/, `sslrootcert=${encodeURIComponent(DUMMY_CA)}`).replace(/<[^>]+>/g, "x");
}

/** The TLS options pg derives from a connection string; constructing the client does not connect. */
function sslOf(connectionString: string): unknown {
  const client = new pg.Client({ connectionString });
  return (client as unknown as { connectionParameters: { ssl: unknown } }).connectionParameters.ssl;
}

describe("README remote connection example", () => {
  it("makes pg verify the server against the CA file named by sslrootcert without weakening verification", () => {
    for (const url of remoteExampleUrls()) {
      const ssl = sslOf(materialize(url));
      assert.ok(ssl !== null && typeof ssl === "object", url);
      assert.equal((ssl as { ca?: unknown }).ca, DUMMY_PEM, url);
      assert.ok(!("rejectUnauthorized" in ssl), url);
      assert.ok(!("checkServerIdentity" in ssl), url);
    }
  });

  // pg 8 treats require / prefer / verify-ca as verify-full with a warning, and pg 9 is to give them libpq's meaning
  it("names sslmode=verify-full explicitly", () => {
    for (const url of remoteExampleUrls()) {
      assert.equal(new URL(materialize(url)).searchParams.get("sslmode"), "verify-full", url);
    }
  });
});
