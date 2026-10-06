import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { analyzeFunction, collectCallTree, extractBody, maskBody, MAX_CALL_DEPTH } from "../src/model/plpgsql.ts";
import type { FunctionAnalysis } from "../src/model/types.ts";
import { def } from "./fixtures.ts";

const analyze = (body: string, known: string[] = [], name = "f") =>
  analyzeFunction({ name, language: "plpgsql", definition: def(name, body) }, "public", new Set([...known, name]));

describe("extractBody", () => {
  it("returns the text between AS $tag$ and the last $tag$, for any tag", () => {
    assert.equal(extractBody(def("f", "BEGIN RETURN NEW; END;", "$body$"))?.trim(), "BEGIN RETURN NEW; END;");
    assert.equal(extractBody("CREATE FUNCTION f() RETURNS int LANGUAGE sql BEGIN ATOMIC SELECT 1; END"), null);
  });
});

describe("maskBody", () => {
  it("blanks comments and literal contents but keeps every offset", () => {
    const src =
      "IF x THEN -- IF y THEN RAISE\n RAISE EXCEPTION 'IF a THEN'; /* RAISE /* nested */ */ END IF; $q$ RAISE $q$";
    const m = maskBody(src);
    assert.equal(m.masked.length, src.length);
    assert.equal(m.code.length, src.length);
    assert.equal(m.masked.match(/RAISE/g)?.length, 1);
    assert.equal(m.masked.match(/\bIF\b/g)?.length, 2);
    assert.ok(m.code.includes("'IF a THEN'"));
    assert.deepEqual(
      m.comments.map((c) => c.text.trim()),
      ["IF y THEN RAISE", "RAISE /* nested */"]
    );
  });

  it("handles E'' escapes and does not treat $1 as a dollar quote", () => {
    const m = maskBody("x := E'it\\'s IF'; y := $1 + $2;");
    assert.ok(!/\bIF\b/.test(m.masked));
    assert.ok(m.masked.includes("$1 + $2"));
  });

  it("throws on unterminated constructs", () => {
    assert.throws(() => maskBody("RAISE EXCEPTION 'oops"));
    assert.throws(() => maskBody("/* open"));
    assert.throws(() => maskBody("x := $a$ never closed"));
  });
});

describe("analyzeFunction guards", () => {
  it("extracts a simple IF ... RAISE EXCEPTION with its condition and message", () => {
    const a = analyze(`
BEGIN
  IF NEW.team_id <> OLD.team_id THEN
    RAISE EXCEPTION 'team_id cannot be changed';
  END IF;
  RETURN NEW;
END;`);
    assert.equal(a.status, "analyzed");
    assert.equal(a.guards.length, 1);
    assert.deepEqual(
      a.guards[0]?.path.map((p) => [p.kind, p.sql]),
      [["IF", "NEW.team_id <> OLD.team_id"]]
    );
    assert.equal(a.guards[0]?.message, "team_id cannot be changed");
    assert.equal(a.earlyReturns.length, 0);
  });

  it("records ELSIF / ELSE branches with the earlier conditions that were false, without synthesizing NOT", () => {
    const a = analyze(`
BEGIN
  IF TG_OP = 'INSERT' THEN
    RETURN NEW;
  ELSIF NEW.status = 'approved' THEN
    RAISE EXCEPTION 'approved rows are frozen';
  ELSE
    RAISE EXCEPTION 'unexpected %', TG_OP;
  END IF;
END;`);
    assert.equal(a.guards.length, 2);
    assert.deepEqual(a.guards[0]?.path[0], {
      kind: "ELSIF",
      sql: "NEW.status = 'approved'",
      notTaken: ["TG_OP = 'INSERT'"]
    });
    assert.deepEqual(a.guards[1]?.path[0]?.kind, "ELSE");
    assert.deepEqual(a.guards[1]?.path[0]?.notTaken, ["TG_OP = 'INSERT'", "NEW.status = 'approved'"]);
    assert.equal(a.guards[1]?.message, "unexpected %");
    assert.equal(a.guards[1]?.arguments, "TG_OP");
    assert.equal(a.earlyReturns[0]?.path[0]?.sql, "TG_OP = 'INSERT'");
  });

  it("keeps the whole path of nested IFs and attaches the comment written above the IF", () => {
    const a = analyze(`
BEGIN
  -- (1) operators may only change status
  IF caller_role = 'operator' THEN
    IF (NEW.name IS DISTINCT FROM OLD.name)
    OR (NEW.id IS DISTINCT FROM OLD.id) THEN
      RAISE EXCEPTION 'operators can only update status'
        USING ERRCODE = 'check_violation', HINT = 'ask an admin';
    END IF;
  END IF;
  RETURN NEW;
END;`);
    const g = a.guards[0];
    assert.equal(g?.path.length, 2);
    assert.equal(g?.path[0]?.comment, "(1) operators may only change status");
    assert.equal(g?.path[1]?.sql, "(NEW.name IS DISTINCT FROM OLD.name) OR (NEW.id IS DISTINCT FROM OLD.id)");
    assert.equal(g?.errcode, "check_violation");
    assert.equal(g?.hint, "ask an admin");
    assert.deepEqual(a.changeCheckedColumns, ["id", "name"]);
    assert.deepEqual(a.headerComments, []);
  });

  it("marks a RAISE outside any IF as unconditional (empty path) and handles RAISE without a level", () => {
    const a = analyze(`
BEGIN
  RAISE 'direct deletes are not allowed' USING ERRCODE = '42501';
END;`);
    assert.deepEqual(a.guards[0]?.path, []);
    assert.equal(a.guards[0]?.message, "direct deletes are not allowed");
    assert.equal(a.guards[0]?.errcode, "42501");
  });

  it("reads RAISE SQLSTATE / condition names and ignores RAISE NOTICE", () => {
    const a = analyze(`
BEGIN
  RAISE NOTICE 'just logging';
  IF NOT FOUND THEN RAISE SQLSTATE 'P0002'; END IF;
  IF x THEN RAISE insufficient_privilege; END IF;
  RETURN NEW;
END;`);
    assert.deepEqual(
      a.guards.map((g) => [g.path[0]?.sql, g.errcode, g.message]),
      [
        ["NOT FOUND", "P0002", null],
        ["x", "insufficient_privilege", null]
      ]
    );
  });

  it("follows CASE statements, loops, nested blocks and exception handlers", () => {
    const a = analyze(`
DECLARE
  r record;
BEGIN
  CASE TG_OP
    WHEN 'DELETE' THEN RAISE EXCEPTION 'no deletes';
    ELSE NULL;
  END CASE;
  FOR r IN SELECT * FROM public.items LOOP
    IF r.locked THEN RAISE EXCEPTION 'locked item %', r.id; END IF;
  END LOOP;
  BEGIN
    x := CASE WHEN a THEN 1 ELSE 2 END;
  EXCEPTION WHEN unique_violation THEN
    RAISE EXCEPTION 'duplicate';
  END;
  <<done>>
  RETURN NEW;
END;`);
    assert.equal(a.status, "analyzed");
    assert.deepEqual(
      a.guards.map((g) => g.path.map((p) => p.kind)),
      [["WHEN"], ["LOOP", "IF"], ["EXCEPTION WHEN"]]
    );
    assert.equal(a.guards[0]?.path[0]?.subject, "TG_OP");
    assert.equal(a.guards[0]?.path[0]?.sql, "'DELETE'");
  });

  it("finds THEN after a CASE expression inside the IF condition", () => {
    const a = analyze(`
BEGIN
  IF CASE WHEN a THEN b ELSE c END THEN RAISE EXCEPTION 'x'; END IF;
  RETURN NEW;
END;`);
    assert.equal(a.guards[0]?.path[0]?.sql, "CASE WHEN a THEN b ELSE c END");
  });

  it("does not report IF / RAISE written inside comments or string literals", () => {
    const a = analyze(`
BEGIN
  -- IF x THEN RAISE EXCEPTION 'commented out'; END IF;
  /* RAISE EXCEPTION 'also commented' */
  PERFORM public.log_event('IF y THEN RAISE EXCEPTION');
  RETURN NEW;
END;`);
    assert.equal(a.guards.length, 0);
    assert.equal(a.unparsedCount, 0);
  });
});

describe("analyzeFunction side effects, columns and calls", () => {
  it("lists INSERT / UPDATE / DELETE targets and ignores FOR UPDATE, DO UPDATE and SQL inside strings", () => {
    const a = analyze(
      `
BEGIN
  INSERT INTO public.audit_log (row_id) VALUES (NEW.id)
    ON CONFLICT (row_id) DO UPDATE SET row_id = EXCLUDED.row_id;
  UPDATE public.documents d SET updated_at = now() WHERE d.id = NEW.document_id;
  DELETE FROM "Items" WHERE id = OLD.id;
  PERFORM 1 FROM public.locks WHERE id = NEW.id FOR UPDATE;
  PERFORM public.notify_change(NEW.id);
  EXECUTE 'DELETE FROM public.hidden';
  RETURN NEW;
END;`,
      ["notify_change"]
    );
    assert.deepEqual(
      a.sideEffects.map((s) => `${s.operation} ${s.schema ?? ""}.${s.name}`),
      ["INSERT public.audit_log", "DELETE .Items", "UPDATE public.documents", "PERFORM public.notify_change"]
    );
    assert.equal(a.dynamicSql, true);
    assert.deepEqual(a.calledFunctions, ["notify_change"]);
  });

  it("collects NEW / OLD columns, and the ones compared for change", () => {
    const a = analyze(`
BEGIN
  IF (NEW.status)::text IS DISTINCT FROM (OLD.status)::text OR NEW.owner != OLD.owner THEN
    NEW.updated_by := NEW."CreatedBy";
  END IF;
  RETURN NEW;
END;`);
    assert.deepEqual(a.newColumns, ["CreatedBy", "owner", "status", "updated_by"]);
    assert.deepEqual(a.oldColumns, ["owner", "status"]);
    assert.deepEqual(a.changeCheckedColumns, ["owner", "status"]);
  });

  it("only reports calls to known functions of the target schema, not keywords or other schemas", () => {
    const a = analyze(
      `
BEGIN
  IF NOT public.is_member(NEW.team) AND coalesce(x, 1) = 1 AND auth.uid() IS NOT NULL AND is_admin() THEN
    RAISE EXCEPTION 'no';
  END IF;
  RETURN NEW;
END;`,
      ["is_member", "is_admin", "uid"]
    );
    assert.deepEqual(a.calledFunctions, ["is_admin", "is_member"]);
  });

  it("keeps the header comment block", () => {
    const a = analyze(`
-- Keeps chat messages in the team of their session.
DECLARE
  t uuid;
BEGIN
  SELECT team_id INTO t FROM public.chat_sessions WHERE id = NEW.session_id;
  RETURN NEW;
END;`);
    assert.deepEqual(a.headerComments, ["Keeps chat messages in the team of their session."]);
  });
});

describe("analyzeFunction call detection on the masked body", () => {
  it("ignores calls written inside comments and string literals", () => {
    const a = analyze(
      `
BEGIN
  -- public.is_admin(NEW.id) used to be checked here
  /* is_member(NEW.team) */
  x := 'is_member(1)';
  y := $q$ public.is_admin(2) $q$;
  RETURN NEW;
END;`,
      ["is_admin", "is_member"]
    );
    assert.deepEqual(a.calledFunctions, []);
  });
});

describe("analyzeFunction review fixes", () => {
  it("does not treat RETURN NEXT / RETURN QUERY as early returns, but keeps a conditional RETURN", () => {
    const a = analyze(`
BEGIN
  IF include_rows THEN
    RETURN NEXT r;
    RETURN QUERY SELECT * FROM public.items;
  END IF;
  IF NEW.id IS NULL THEN
    RETURN NULL;
  END IF;
  RETURN NEW;
END;`);
    assert.deepEqual(
      a.earlyReturns.map((r) => r.statement),
      ["RETURN NULL"]
    );
  });

  it("reads an E'' message and decodes its backslash escapes", () => {
    const a = analyze(String.raw`
BEGIN
  IF x THEN RAISE EXCEPTION E'line1\nit\'s a \\ path %', NEW.id; END IF;
  IF y THEN RAISE EXCEPTION e'tab\there' USING ERRCODE = 'check_violation'; END IF;
  RETURN NEW;
END;`);
    assert.equal(a.guards[0]?.message, "line1\nit's a \\ path %");
    assert.equal(a.guards[0]?.arguments, "NEW.id");
    assert.equal(a.guards[0]?.errcode, null);
    assert.equal(a.guards[1]?.message, "tab\there");
    assert.equal(a.guards[1]?.errcode, "check_violation");
  });

  it("scans 100,000 whitespace characters between NEW / OLD comparisons in linear time", () => {
    const body = `BEGIN IF NEW.a${" ".repeat(100_000)}= 1 OR OLD.b${" ".repeat(100_000)}<> 2 THEN RAISE EXCEPTION 'x'; END IF; RETURN NEW; END;`;
    const started = performance.now();
    const a = analyze(body);
    const elapsed = performance.now() - started;
    assert.equal(a.guards.length, 1);
    assert.ok(elapsed < 100, `took ${elapsed.toFixed(1)} ms`);
  });
});

describe("analyzeFunction fallbacks", () => {
  it("reports failed (not a crash) when the control flow cannot be followed", () => {
    const a = analyze(`
BEGIN
  IF broken THEN
    RAISE EXCEPTION 'never closed';
  RETURN NEW;
END;`);
    assert.equal(a.status, "failed");
    assert.ok(a.reason);
    assert.equal(a.guards.length, 0);
    assert.equal(a.unparsedCount, 1);
  });

  it("reports failed for an unterminated literal and unsupported for other languages", () => {
    assert.equal(analyze("BEGIN RAISE EXCEPTION 'oops; END;").status, "failed");
    const c = analyzeFunction({ name: "c", language: "c", definition: "CREATE FUNCTION c() ..." }, "public", new Set());
    assert.equal(c.status, "unsupported");
    const sql = analyzeFunction(
      {
        name: "is_member",
        language: "sql",
        definition:
          "CREATE FUNCTION public.is_member(team uuid) RETURNS boolean LANGUAGE sql AS $function$ SELECT public.helper(team) $function$"
      },
      "public",
      new Set(["helper"])
    );
    assert.equal(sql.status, "unsupported");
    assert.deepEqual(sql.calledFunctions, ["helper"]);
  });
});

describe("collectCallTree", () => {
  const node = (calls: string[]): FunctionAnalysis => ({
    status: "analyzed",
    reason: null,
    guards: [],
    earlyReturns: [],
    sideEffects: [],
    newColumns: [],
    oldColumns: [],
    changeCheckedColumns: [],
    calledFunctions: calls,
    headerComments: [],
    dynamicSql: false,
    unparsedCount: 0
  });

  it("follows a 3-level chain and records the via path", () => {
    const graph: Record<string, string[]> = { trg: ["a"], a: ["b"], b: ["c"], c: [] };
    const tree = collectCallTree("trg", (n) => (graph[n] ? node(graph[n]) : undefined));
    assert.deepEqual(
      tree.entries.map((e) => [e.name, e.depth, e.via.join(">")]),
      [
        ["trg", 0, ""],
        ["a", 1, "a"],
        ["b", 2, "a>b"],
        ["c", 3, "a>b>c"]
      ]
    );
    assert.deepEqual(tree.truncated, []);
  });

  it("stops at cycles and reports them as truncated", () => {
    const graph: Record<string, string[]> = { trg: ["a"], a: ["b"], b: ["a", "trg"] };
    const tree = collectCallTree("trg", (n) => (graph[n] ? node(graph[n]) : undefined));
    assert.deepEqual(
      tree.entries.map((e) => e.name),
      ["trg", "a", "b"]
    );
    assert.deepEqual(tree.truncated, [
      { from: "b", to: "a", reason: "cycle" },
      { from: "b", to: "trg", reason: "cycle" }
    ]);
  });

  it("visits a function reached through two paths only once", () => {
    const graph: Record<string, string[]> = { trg: ["a", "b"], a: ["shared"], b: ["shared"], shared: [] };
    const tree = collectCallTree("trg", (n) => (graph[n] ? node(graph[n]) : undefined));
    assert.equal(tree.entries.filter((e) => e.name === "shared").length, 1);
    assert.deepEqual(tree.truncated, [{ from: "b", to: "shared", reason: "visited" }]);
  });

  it(`truncates a chain longer than MAX_CALL_DEPTH (${MAX_CALL_DEPTH})`, () => {
    const chain = Array.from({ length: MAX_CALL_DEPTH + 3 }, (_, i) => `f${i}`);
    const tree = collectCallTree("f0", (n) => {
      const i = chain.indexOf(n);
      return i < 0 ? undefined : node(i + 1 < chain.length ? [chain[i + 1] as string] : []);
    });
    assert.equal(Math.max(...tree.entries.map((e) => e.depth)), MAX_CALL_DEPTH);
    assert.deepEqual(tree.truncated, [{ from: `f${MAX_CALL_DEPTH}`, to: `f${MAX_CALL_DEPTH + 1}`, reason: "depth" }]);
  });
});
