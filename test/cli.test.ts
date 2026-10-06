import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { createServer, type Socket } from "node:net";
import { join } from "node:path";
import { after, describe, it } from "node:test";
import { EXIT_DB, EXIT_OK, EXIT_USAGE, main, type CliIo } from "../src/cli.ts";
import { anchorId } from "../src/render/html.ts";
import { doc, pgUrl, policy, table } from "./fixtures.ts";

// Work under the git-ignored out/ directory
const outRoot = join(import.meta.dirname, "..", "out");
mkdirSync(outRoot, { recursive: true });
const work = mkdtempSync(join(outRoot, "test-cli-"));
after(() => rmSync(work, { recursive: true, force: true }));

function io(env: NodeJS.ProcessEnv = {}): CliIo & { err: string[]; out: string[] } {
  const err: string[] = [];
  const out: string[] = [];
  return { err, out, stdout: (s) => out.push(s), stderr: (s) => err.push(s), env, cwd: work };
}

/** Picks an unused local port so that the connection is reliably refused. */
async function freePort(): Promise<number> {
  return new Promise((resolve) => {
    const srv = createServer();
    srv.listen(0, "127.0.0.1", () => {
      const addr = srv.address();
      const port = typeof addr === "object" && addr ? addr.port : 0;
      srv.close(() => resolve(port));
    });
  });
}

/** Serializes a backend ErrorResponse message ('E') from single-byte field codes. */
function errorResponse(fields: Record<string, string>): Buffer {
  const body = Buffer.concat([
    ...Object.entries(fields).map(([code, value]) => Buffer.from(`${code}${value}\0`)),
    Buffer.from([0])
  ]);
  const length = Buffer.alloc(4);
  length.writeInt32BE(body.length + 4);
  return Buffer.concat([Buffer.from("E"), length, body]);
}

/**
 * A loopback server that answers the startup message with a FATAL ErrorResponse and leaves the socket open, so
 * `closed` settles only when the client ends the connection. With allowHalfOpen false (the default) the client's FIN is
 * what closes the server side; with true the server never closes it.
 */
async function listenRejectingStartup({ allowHalfOpen = false } = {}): Promise<{
  port: number;
  closed: Promise<void>;
  stop(): Promise<void>;
}> {
  const sockets: Socket[] = [];
  let markClosed: () => void = () => {};
  const closed = new Promise<void>((resolve) => (markClosed = resolve));
  const server = createServer({ allowHalfOpen }, (socket) => {
    sockets.push(socket);
    socket.once("close", () => markClosed());
    socket.once("data", () => {
      socket.write(errorResponse({ S: "FATAL", V: "FATAL", C: "28P01", M: "password authentication failed" }));
    });
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const addr = server.address();
  const port = typeof addr === "object" && addr ? addr.port : 0;
  const stop = async (): Promise<void> => {
    for (const s of sockets) s.destroy();
    await new Promise<void>((resolve) => server.close(() => resolve()));
  };
  return { port, closed, stop };
}

/** Resolves true when the promise settles within ms, false otherwise. */
async function withinMs(promise: Promise<unknown>, ms: number): Promise<boolean> {
  let timer: NodeJS.Timeout | undefined;
  const timeout = new Promise<boolean>((resolve) => (timer = setTimeout(() => resolve(false), ms)));
  try {
    return await Promise.race([promise.then(() => true), timeout]);
  } finally {
    clearTimeout(timer);
  }
}

describe("cli", () => {
  it("exits with the connection code (2) when the database is unreachable and keeps the URL out of the log", async () => {
    const port = await freePort();
    const c = io();
    const code = await main(["extract", "--db-url", pgUrl({ user: "postgres", password: "topsecret", port })], c);
    assert.equal(code, EXIT_DB);
    const log = c.err.join("");
    assert.ok(log.includes("Could not connect to the database"));
    assert.ok(!log.includes("topsecret"));
  });

  it("exits with the usage code (1) for a non-loopback host", async () => {
    const c = io({ DATABASE_URL: pgUrl({ user: "u", password: "p", host: "db.example.com", db: "x" }) });
    assert.equal(await main(["generate"], c), EXIT_USAGE);
  });

  it("exits with the usage code (1) without a connection target", async () => {
    assert.equal(await main(["extract"], io()), EXIT_USAGE);
  });

  it("exits with the usage code (1) and names the missing supabase/config.toml when --from-supabase-status points --project-dir at a missing directory", async () => {
    const c = io();
    const code = await main(["extract", "--from-supabase-status", "--project-dir", "no-such-project"], c);
    assert.equal(code, EXIT_USAGE);
    const log = c.err.join("");
    assert.ok(log.includes("supabase/config.toml not found"));
    assert.ok(log.includes(join(work, "no-such-project"))); // resolved against io.cwd by cli.ts
    assert.ok(!log.includes("supabase CLI not found"));
  });

  it("render generates HTML from rules.json", async () => {
    const inPath = join(work, "rules.json");
    writeFileSync(
      inPath,
      JSON.stringify(
        doc({ tables: [table({ name: "t1", policies: [policy({ name: "p", command: "ALL", using: "true" })] })] })
      )
    );
    const code = await main(["render", "--in", "rules.json", "--out", "view/index.html"], io());
    assert.equal(code, EXIT_OK);
    const html = readFileSync(join(work, "view", "index.html"), "utf8");
    assert.ok(html.startsWith("<!doctype html>"));
    assert.ok(html.includes(`id="${anchorId("t", "t1")}"`));
    assert.ok(html.includes(`id="${anchorId("c", "t1", "SELECT")}"`));
  });

  it("rejects rules.json with another formatVersion", async () => {
    writeFileSync(join(work, "bad.json"), JSON.stringify({ formatVersion: 99 }));
    assert.equal(await main(["render", "--in", "bad.json"], io()), EXIT_USAGE);
  });

  it("rejects crafted rules.json files with RulesDocumentError instead of crashing the renderer", async () => {
    const valid = () =>
      doc({
        tables: [table({ name: "t1", policies: [policy({ name: "p", command: "ALL", using: "true" })] })],
        views: [
          {
            name: "v",
            kind: "view",
            securityInvoker: true,
            securityBarrier: false,
            definition: "SELECT 1",
            baseRelations: [],
            grants: []
          }
        ]
      }) as unknown as Record<string, unknown>;
    const first = (d: Record<string, unknown>, key: string) =>
      (d[key] as Record<string, unknown>[])[0] as Record<string, unknown>;
    const cases: [string, (d: Record<string, unknown>) => void][] = [
      ["a table without rls", (d) => delete first(d, "tables").rls],
      ["rls.enabled is a string", (d) => ((first(d, "tables").rls as Record<string, unknown>).enabled = "yes")],
      ["policies is not an array", (d) => (first(d, "tables").policies = {})],
      [
        "a policy command is unknown",
        (d) =>
          (((first(d, "tables").policies as Record<string, unknown>[])[0] as Record<string, unknown>).command = "MERGE")
      ],
      ["grants hold a number", (d) => (first(d, "tables").grants = [1])],
      ["a view lacks securityInvoker", (d) => delete first(d, "views").securityInvoker],
      ["roles is not an array", (d) => (d.roles = "anon")],
      ["excluded counts are strings", (d) => ((d.excluded as Record<string, unknown>).extensionOwnedFunctions = "143")],
      ["source.serverVersion is missing", (d) => delete (d.source as Record<string, unknown>).serverVersion]
    ];
    for (const [label, mutate] of cases) {
      const d = valid();
      mutate(d);
      writeFileSync(join(work, "crafted.json"), JSON.stringify(d));
      const c = io();
      const code = await main(["render", "--in", "crafted.json", "--out", "crafted.html"], c);
      const log = c.err.join("");
      assert.equal(code, EXIT_USAGE, label);
      assert.ok(!log.includes("Unexpected error"), `${label}: ${log}`);
      assert.ok(!log.includes("TypeError"), `${label}: ${log}`);
    }
  });

  it("still renders a rules.json that matches the schema", async () => {
    writeFileSync(join(work, "valid.json"), JSON.stringify(doc({ tables: [table({ name: "t1" })] })));
    assert.equal(await main(["render", "--in", "valid.json", "--out", "valid.html"], io()), EXIT_OK);
  });

  it("treats unknown commands and options as usage errors", async () => {
    assert.equal(await main(["nope"], io()), EXIT_USAGE);
    assert.equal(await main(["render", "--unknown"], io()), EXIT_USAGE);
    assert.equal(await main(["--help"], io()), EXIT_OK);
  });

  it("lists --db-url-file in the usage and warns against passwords in --db-url", async () => {
    const c = io();
    await main(["--help"], c);
    const usage = c.out.join("");
    assert.ok(usage.includes("--db-url-file <path>"));
    assert.ok(usage.includes("Precedence: --db-url or --db-url-file, then DATABASE_URL, then --from-supabase-status"));
    assert.ok(usage.includes("Do not put a password in it"));
  });

  it("rejects an empty --db-url / --db-url-file as a usage error instead of falling back to DATABASE_URL", async () => {
    const env = { DATABASE_URL: pgUrl({ user: "u", password: "p", host: "db.example.com", db: "x" }) };
    for (const args of [
      ["extract", "--db-url-file", ""],
      ["extract", "--db-url", ""],
      ["extract", "--db-url", "  "]
    ]) {
      const c = io(env);
      assert.equal(await main(args, c), EXIT_USAGE, args.join(" "));
      assert.ok(c.err.join("").includes("must not be empty"), args.join(" "));
    }
  });

  it("rejects an empty --project-dir as a usage error instead of searching upward", async () => {
    const c = io();
    assert.equal(await main(["extract", "--from-supabase-status", "--project-dir", ""], c), EXIT_USAGE);
    assert.ok(c.err.join("").includes("must not be empty"));
  });

  it("rejects --db-url together with --db-url-file as a usage error", async () => {
    const c = io();
    const code = await main(["extract", "--db-url", "postgresql://u@127.0.0.1/x", "--db-url-file", "x.url"], c);
    assert.equal(code, EXIT_USAGE);
    assert.ok(c.err.join("").includes("cannot be used together"));
  });

  it("exits with the connection code (2) and prints the --db-url password warning once, without the password or the URL", async () => {
    const port = await freePort();
    const c = io();
    const code = await main(["extract", "--db-url", pgUrl({ user: "postgres", password: "cli-secret-pw", port })], c);
    assert.equal(code, EXIT_DB);
    const log = c.err.join("");
    assert.equal(log.split("--db-url contains a password").length - 1, 1);
    assert.ok(!log.includes("cli-secret-pw"));
    assert.ok(!log.includes("postgresql://"));
  });

  it("reads --db-url-file relative to the working directory and exits with the usage code (1) on a missing file without a password warning", async () => {
    const c = io();
    assert.equal(await main(["extract", "--db-url-file", "no-such.url"], c), EXIT_USAGE);
    const log = c.err.join("");
    assert.ok(log.includes(join(work, "no-such.url")));
    assert.ok(!log.includes("contains a password"));
  });

  // pg rejects these while constructing the client, before opening a socket; the free port keeps the test off a real
  // database if pg ever defers the check to connect()
  it("exits with the usage code (1) and reports invalid connection settings when the password has an invalid percent-encoding, without the password or the URL", async () => {
    const port = await freePort();
    const c = io({ DATABASE_URL: pgUrl({ user: "postgres", password: "sec%E0ret", port }) });
    const code = await main(["extract"], c);
    const log = c.err.join("");
    assert.ok(log.includes("Error: Invalid connection settings: URI malformed"), log);
    assert.ok(!log.includes("Unexpected error"), log);
    assert.equal(code, EXIT_USAGE);
    assert.ok(!log.includes("sec%E0ret"));
    assert.ok(!log.includes("postgresql://"));
  });

  it("exits with the usage code (1) and relays pg's message verbatim when sslrootcert points at a missing file", async () => {
    const port = await freePort();
    const ca = join(work, "no-such-ca.pem");
    const c = io({
      DATABASE_URL: pgUrl({ user: "postgres", password: "pw", port, query: `sslrootcert=${encodeURIComponent(ca)}` })
    });
    const code = await main(["extract"], c);
    const log = c.err.join("");
    assert.ok(log.includes("Error: Invalid connection settings: ENOENT: no such file or directory, open '"), log);
    assert.ok(!log.includes("Unexpected error"), log);
    assert.equal(code, EXIT_USAGE);
    assert.ok(!log.includes("postgresql://"));
  });

  // sslmode=disable keeps a PGSSLMODE in the real environment from sending pg down the SSL path, which closes the
  // socket by itself; the password keeps pg from reading ~/.pgpass
  it("exits with the connection code (2) and closes the connection when the server rejects the startup with an ErrorResponse but keeps the socket open", async () => {
    const server = await listenRejectingStartup();
    try {
      const c = io({
        DATABASE_URL: pgUrl({
          user: "postgres",
          password: "fake-server-pw",
          port: server.port,
          query: "sslmode=disable"
        })
      });
      const code = await main(["extract"], c);
      const released = await withinMs(server.closed, 2000);
      const log = c.err.join("");
      assert.equal(code, EXIT_DB);
      assert.ok(log.includes("Could not connect to the database: 28P01"), log);
      assert.ok(!log.includes("fake-server-pw"));
      assert.ok(!log.includes("postgresql://"));
      assert.equal(released, true, "the server side of the connection was not closed within 2s");
    } finally {
      await server.stop();
    }
  });

  it("exits with the connection code (2) without waiting for a server that keeps the socket half-open after the client ends it", async () => {
    const server = await listenRejectingStartup({ allowHalfOpen: true });
    try {
      const c = io({
        DATABASE_URL: pgUrl({
          user: "postgres",
          password: "fake-server-pw",
          port: server.port,
          query: "sslmode=disable"
        })
      });
      let code: number | undefined;
      const returned = await withinMs(
        main(["extract"], c).then((value) => (code = value)),
        2000
      );
      const log = c.err.join("");
      assert.equal(returned, true, "main() did not return within 2s");
      assert.equal(code, EXIT_DB);
      assert.ok(log.includes("Could not connect to the database: 28P01"), log);
      assert.ok(!log.includes("fake-server-pw"));
      assert.ok(!log.includes("postgresql://"));
    } finally {
      await server.stop();
    }
  });
});
