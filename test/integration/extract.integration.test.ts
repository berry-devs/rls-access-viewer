import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { join } from "node:path";
import { after, before, describe, it } from "node:test";
import pg from "pg";
import { EXIT_OK, main } from "../../src/cli.ts";
import { connectsOnlyToLoopback } from "../../src/extract/connection.ts";
import { extractRules, extractStorage, resolveDbUrl } from "../../src/extract/index.ts";
import { extractBody } from "../../src/model/plpgsql.ts";
import { buildCell, buildReverseFkIndex } from "../../src/model/cells.ts";
import { OPERATIONS, type RulesDocument } from "../../src/model/types.ts";
import { anchorId } from "../../src/render/html.ts";
import { loadRulesSchema, validate } from "../../src/model/schema.ts";

/**
 * Runs against a real database (DATABASE_URL). Expected values are computed with independent,
 * simple catalog queries rather than hard-coded, so the test survives schema changes.
 */
const DATABASE_URL = process.env.DATABASE_URL;
const SCHEMA = process.env.RLS_ACCESS_VIEWER_SCHEMA ?? "public";

// The suite runs DDL (DROP SCHEMA ... CASCADE), so fail the whole file before any connection rather than skip,
// using the same host rules as the CLI (pg reads PGHOST from process.env, so check against it)
if (DATABASE_URL && !connectsOnlyToLoopback(DATABASE_URL, process.env)) {
  throw new Error(
    "DATABASE_URL points at a non-loopback host. The integration tests run DDL such as DROP SCHEMA ... CASCADE, " +
      "so they only run against a disposable local database (localhost, 127.0.0.0/8, ::1 or a UNIX socket)"
  );
}

describe("extract → render against a live database", { skip: DATABASE_URL ? false : "DATABASE_URL is not set" }, () => {
  const outRoot = join(import.meta.dirname, "..", "..", "out");
  let work = "";
  let doc: RulesDocument;
  let json = "";
  let html = "";
  const client = new pg.Client({ connectionString: DATABASE_URL });
  const one = async (sql: string): Promise<Record<string, number>> => {
    const r = await client.query(sql, [SCHEMA]);
    return r.rows[0] as Record<string, number>;
  };
  const NOT_EXT = (cls: string, oid: string) =>
    `NOT EXISTS (SELECT 1 FROM pg_depend d WHERE d.classid = '${cls}'::regclass AND d.objid = ${oid} AND d.deptype = 'e')`;

  before(async () => {
    mkdirSync(outRoot, { recursive: true });
    work = mkdtempSync(join(outRoot, "test-integration-"));
    const err: string[] = [];
    const code = await main(["generate", "--out-dir", work, "--schema", SCHEMA], {
      stdout: () => {},
      stderr: (s) => err.push(s),
      env: { DATABASE_URL },
      cwd: work
    });
    assert.equal(code, EXIT_OK, err.join(""));
    json = readFileSync(join(work, "rules.json"), "utf8");
    html = readFileSync(join(work, "index.html"), "utf8");
    doc = JSON.parse(json) as RulesDocument;
    await client.connect();
  });

  after(async () => {
    await client.end();
    if (work) rmSync(work, { recursive: true, force: true });
  });

  it("conforms to schemas/rules.schema.json", () => {
    assert.deepEqual(validate(loadRulesSchema(), doc).slice(0, 5), []);
  });

  it("extracts every table, view and policy of the schema", async () => {
    const c = await one(`SELECT
      count(*) FILTER (WHERE relkind IN ('r','p') AND ${NOT_EXT("pg_class", "c.oid")})::int AS tables,
      count(*) FILTER (WHERE relkind IN ('v','m') AND ${NOT_EXT("pg_class", "c.oid")})::int AS views,
      count(*) FILTER (WHERE relkind IN ('r','p') AND NOT relrowsecurity)::int AS rls_off
      FROM pg_class c WHERE relnamespace = $1::regnamespace`);
    assert.equal(doc.tables.length, c.tables);
    assert.equal(doc.views.length, c.views);
    assert.equal(doc.tables.filter((t) => !t.rls.enabled).length, c.rls_off);

    const p = await one(`SELECT count(*)::int AS total,
      count(*) FILTER (WHERE cmd = 'ALL')::int AS all_cmd,
      count(*) FILTER (WHERE permissive = 'RESTRICTIVE')::int AS restrictive
      FROM pg_policies WHERE schemaname = $1`);
    const policies = doc.tables.flatMap((t) => t.policies);
    assert.equal(policies.length, p.total);
    assert.equal(policies.filter((x) => x.command === "ALL").length, p.all_cmd);
    assert.equal(policies.filter((x) => !x.permissive).length, p.restrictive);
  });

  it("expands every ALL policy into all four operation cells", () => {
    const idx = buildReverseFkIndex(doc);
    const allPolicies = doc.tables.reduce((n, t) => n + t.policies.filter((p) => p.command === "ALL").length, 0);
    let expanded = 0;
    for (const t of doc.tables) {
      for (const op of OPERATIONS) expanded += buildCell(doc, t, op, idx).policies.filter((p) => p.fromAll).length;
    }
    assert.equal(expanded, allPolicies * 4);
  });

  it("matches SECURITY DEFINER, foreign key and trigger counts", async () => {
    const f = await one(`SELECT count(*)::int AS secdef,
      count(*) FILTER (WHERE NOT EXISTS (SELECT 1 FROM unnest(p.proconfig) cfg WHERE cfg LIKE 'search_path=%'))::int AS no_path
      FROM pg_proc p WHERE pronamespace = $1::regnamespace AND prosecdef AND ${NOT_EXT("pg_proc", "p.oid")}`);
    const secdef = doc.functions.filter((x) => x.securityDefiner);
    assert.equal(secdef.length, f.secdef);
    assert.equal(secdef.filter((x) => x.searchPath === null).length, f.no_path);

    const k = await one(`SELECT count(*)::int AS fks, count(*) FILTER (WHERE confdeltype = 'c')::int AS cascade
      FROM pg_constraint con JOIN pg_class c ON c.oid = con.conrelid
      WHERE con.contype = 'f' AND c.relnamespace = $1::regnamespace AND c.relkind IN ('r','p')`);
    const fks = doc.tables.flatMap((t) => t.constraints).filter((c) => c.kind === "foreign");
    assert.equal(fks.length, k.fks);
    assert.equal(fks.filter((c) => c.kind === "foreign" && c.onDelete === "CASCADE").length, k.cascade);

    const t = await one(`SELECT count(*)::int AS triggers FROM pg_trigger tg JOIN pg_class c ON c.oid = tg.tgrelid
      WHERE c.relnamespace = $1::regnamespace AND c.relkind IN ('r','p') AND NOT tg.tgisinternal`);
    assert.equal(
      doc.tables.reduce((n, x) => n + x.triggers.length, 0),
      t.triggers
    );
  });

  it("excludes extension-owned functions and platform event triggers", async () => {
    const e = await one(`SELECT count(*)::int AS ext FROM pg_proc p
      WHERE pronamespace = $1::regnamespace AND NOT ${NOT_EXT("pg_proc", "p.oid")}`);
    assert.equal(doc.excluded.extensionOwnedFunctions, e.ext);
    const names = new Set(doc.functions.map((x) => x.name));
    const extNames = await client.query(
      `SELECT DISTINCT proname FROM pg_proc p WHERE pronamespace = $1::regnamespace AND NOT ${NOT_EXT("pg_proc", "p.oid")}
       AND NOT EXISTS (SELECT 1 FROM pg_proc q WHERE q.proname = p.proname AND q.pronamespace = p.pronamespace AND ${NOT_EXT("pg_proc", "q.oid")})`,
      [SCHEMA]
    );
    for (const r of extNames.rows as { proname: string }[]) assert.ok(!names.has(r.proname), r.proname);
    assert.ok(doc.eventTriggers.every((x) => x.owner !== "supabase_admin"));
  });

  it("analyzes every PL/pgSQL trigger function without failing and finds guards where RAISE EXCEPTION is used", async () => {
    const triggerFns = new Set(
      doc.tables.flatMap((t) => t.triggers.filter((x) => x.function.schema === SCHEMA).map((x) => x.function.name))
    );
    const plpgsql = doc.functions.filter((f) => triggerFns.has(f.name) && f.language === "plpgsql");
    assert.ok(plpgsql.length > 0);
    for (const f of plpgsql) assert.notEqual(f.analysis?.status, "failed", `${f.name}: ${f.analysis?.reason}`);
    const raising = plpgsql.filter((f) => /\bRAISE\s+EXCEPTION\b/i.test(f.definition ?? ""));
    const guarded = raising.filter((f) => (f.analysis?.guards.length ?? 0) > 0);
    const partial = plpgsql.filter((f) => f.analysis?.status === "partial").length;
    console.log(
      `trigger functions: ${plpgsql.length} plpgsql, ${raising.length} with RAISE EXCEPTION, ${guarded.length} with guards, ${partial} partial`
    );
    // Loose on purpose: the counts depend on the database; nearly every raising function should yield a guard
    if (raising.length > 0) assert.ok(guarded.length / raising.length >= 0.9);
  });

  it("extracts exactly prosrc as the body of every PL/pgSQL function", async () => {
    const r = await client.query(
      `SELECT p.proname, pg_get_function_identity_arguments(p.oid) AS args, p.prosrc FROM pg_proc p
       JOIN pg_language l ON l.oid = p.prolang
       WHERE p.pronamespace = (SELECT oid FROM pg_namespace WHERE nspname = $1) AND l.lanname = 'plpgsql'`,
      [SCHEMA]
    );
    const byKey = new Map(doc.functions.map((f) => [`${f.name}(${f.identityArguments})`, f]));
    for (const row of r.rows as { proname: string; args: string; prosrc: string }[]) {
      const f = byKey.get(`${row.proname}(${row.args})`);
      // rules.json is redacted, so only compare bodies the redaction left untouched
      if (!f?.definition || f.definition.includes("[REDACTED]")) continue;
      assert.equal(extractBody(f.definition), row.prosrc, row.proname);
    }
  });

  it("renders a detail section for every table × operation", () => {
    for (const t of doc.tables) {
      for (const op of OPERATIONS) assert.ok(html.includes(`id="${anchorId("c", t.name, op)}"`), `${t.name}/${op}`);
    }
  });

  it("extracts storage.buckets settings and storage.objects rules, with a Storage cell per bucket and operation", async (t) => {
    const ns = await client.query("SELECT 1 FROM pg_namespace WHERE nspname = 'storage'");
    if (!ns.rowCount) {
      t.skip("the database has no storage schema");
      return;
    }
    const buckets = await client.query("SELECT count(*)::int AS n FROM storage.buckets");
    const policies = await client.query(
      "SELECT count(*)::int AS n FROM pg_policy WHERE polrelid = 'storage.objects'::regclass"
    );
    assert.equal(doc.storage?.buckets.length, buckets.rows[0].n);
    assert.equal(doc.storage?.objects?.policies.length, policies.rows[0].n);
    assert.ok(html.includes('id="tab-storage"'));
    for (const b of doc.storage?.buckets ?? []) {
      for (const op of OPERATIONS) assert.ok(html.includes(`id="${anchorId("s", b.id, op)}"`), `${b.id}/${op}`);
    }
  });

  it("reports bucket settings as unreadable for a role that row security filters to no buckets", async (t) => {
    const ns = await client.query("SELECT to_regclass('storage.buckets') IS NOT NULL AS ok");
    if (!ns.rows[0]?.ok) {
      t.skip("the database has no storage.buckets");
      return;
    }
    // anon holds the column privileges, but storage.buckets has RLS enabled and (by default) no policy for it
    await client.query("BEGIN");
    try {
      await client.query("SET LOCAL ROLE anon");
      const visible = await client.query("SELECT count(*)::int AS n FROM storage.buckets");
      const raw = await extractStorage(async (sql, params = []) => (await client.query(sql, params)).rows);
      if (visible.rows[0].n > 0) {
        assert.equal(raw?.bucketsReadable, true);
        assert.equal(raw?.bucketsFiltered, true);
      } else {
        assert.equal(raw?.bucketsReadable, false);
        assert.deepEqual(raw?.buckets, []);
      }
    } finally {
      await client.query("ROLLBACK");
    }
    assert.equal(doc.storage?.bucketsReadable, true);
  });

  it("contains no connection string, JWT or other literal secret", () => {
    assert.ok(DATABASE_URL);
    for (const out of [json, html]) {
      assert.ok(!out.includes(DATABASE_URL));
      assert.ok(!/postgres(ql)?:\/\//i.test(out));
      assert.ok(!/eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\./.test(out));
      assert.ok(!/\bsk-[A-Za-z0-9_-]{16,}/.test(out));
      // Short passwords such as the local default "postgres" collide with role names, so only check distinctive ones
      const password = decodeURIComponent(new URL(DATABASE_URL).password);
      if (password.length >= 12) assert.ok(!out.includes(password));
    }
  });
});

describe("password supplied through PGPASSWORD", { skip: DATABASE_URL ? false : "DATABASE_URL is not set" }, () => {
  it("connects with a password-less URL when PGPASSWORD holds the password (read only)", async (t) => {
    const url = new URL(DATABASE_URL as string);
    const password = decodeURIComponent(url.password);
    if (!password) {
      t.skip("DATABASE_URL has no password to move into PGPASSWORD");
      return;
    }
    url.password = "";
    const previous = process.env.PGPASSWORD;
    // pg reads PGPASSWORD from process.env when the connection string has no password
    process.env.PGPASSWORD = password;
    try {
      const passwordless = url.toString();
      assert.equal(resolveDbUrl({ dbUrl: passwordless, env: process.env }), passwordless);
      const doc = await extractRules({ connectionString: passwordless, schema: SCHEMA });
      assert.ok(doc.tables.length > 0);
    } finally {
      if (previous === undefined) delete process.env.PGPASSWORD;
      else process.env.PGPASSWORD = previous;
    }
  });
});

describe("schema names with upper case", { skip: DATABASE_URL ? false : "DATABASE_URL is not set" }, () => {
  // Quoted identifier: $1::regnamespace would fold it to "rlsaccessviewermixedcase" and fail to find it
  const MIXED = "RlsAccessViewerMixedCase";
  const client = new pg.Client({ connectionString: DATABASE_URL });

  before(async () => {
    await client.connect();
    // DDL only (no GRANT / role changes); created outside extract's READ ONLY transaction and dropped in after()
    await client.query(`DROP SCHEMA IF EXISTS "${MIXED}" CASCADE`);
    await client.query(`CREATE SCHEMA "${MIXED}"`);
    await client.query(`CREATE TABLE "${MIXED}"."Items" (id int PRIMARY KEY, owner uuid)`);
    await client.query(`ALTER TABLE "${MIXED}"."Items" ENABLE ROW LEVEL SECURITY`);
    await client.query(`CREATE POLICY "own items" ON "${MIXED}"."Items" FOR SELECT USING (owner IS NOT NULL)`);
  });

  after(async () => {
    await client.query(`DROP SCHEMA IF EXISTS "${MIXED}" CASCADE`);
    await client.end();
  });

  it("extracts a schema whose name needs quoting", async () => {
    const doc = await extractRules({ connectionString: DATABASE_URL as string, schema: MIXED });
    assert.equal(doc.source.schema, MIXED);
    assert.deepEqual(
      doc.tables.map((t) => t.name),
      ["Items"]
    );
    assert.deepEqual(
      doc.tables[0]?.policies.map((p) => p.name),
      ["own items"]
    );
    assert.equal(doc.tables[0]?.constraints[0]?.kind, "primary");
  });
});
