import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { assembleDocument, type RawCatalog } from "../src/extract/index.ts";
import { compileTags, loadConfig } from "../src/model/config.ts";
import { analyzeFunction } from "../src/model/plpgsql.ts";
import { redactDeep } from "../src/model/redact.ts";
import type { FunctionInfo } from "../src/model/types.ts";
import { assertRulesDocument, RulesDocumentError } from "../src/model/validate.ts";
import { anchorId, renderHtml } from "../src/render/html.ts";
import { def, doc, pgUrl, table, trigger } from "./fixtures.ts";
import { loadRulesSchema, validate } from "../src/model/schema.ts";

const tags = compileTags(loadConfig());
const META = "<meta http-equiv=refresh content=0;url=https://attacker.example>";
const JWT = "eyJhbGciOiJIUzI1NiJ9.eyJyb2xlIjoic2VydmljZV9yb2xlIn0.c2lnbmF0dXJlX3NpZ25hdHVyZQ";

function fn(name: string, body: string, extra: Partial<FunctionInfo> = {}): FunctionInfo {
  return {
    name,
    identityArguments: "",
    returns: "trigger",
    kind: "function",
    language: "plpgsql",
    volatility: "VOLATILE",
    securityDefiner: false,
    searchPath: "",
    executableBy: { anon: false, authenticated: true },
    definition: def(name, body),
    ...extra
  };
}

/** Cuts the cell section of a table / operation. */
function cell(html: string, tableName: string, op: string): string {
  const id = `id="${anchorId("c", tableName, op)}"`;
  const start = html.indexOf(id);
  assert.ok(start >= 0);
  return html.slice(start, html.indexOf("</section>", start));
}

describe("trigger function rules in the viewer", () => {
  const functions = [
    fn(
      "guard_items",
      `
BEGIN
  -- Locked rows cannot change
  IF OLD.locked AND NEW.locked IS NOT DISTINCT FROM OLD.locked THEN
    RAISE EXCEPTION 'locked items cannot be updated' USING ERRCODE = 'check_violation';
  END IF;
  PERFORM public.check_owner(NEW.owner);
  INSERT INTO public.item_history (item_id) VALUES (NEW.id);
  RETURN NEW;
END;`
    ),
    fn(
      "check_owner",
      `
BEGIN
  IF NOT public.is_owner(owner_id) THEN
    RAISE EXCEPTION 'only the owner may change the item';
  END IF;
END;`
    ),
    fn("is_owner", "BEGIN RETURN true; END;"),
    fn("broken_fn", "BEGIN IF x THEN RAISE EXCEPTION 'unclosed'; RETURN NEW; END;")
  ];
  const d = doc({
    tables: [
      table({
        name: "items",
        triggers: [
          trigger({
            name: "items_guard",
            events: ["UPDATE"],
            function: { schema: "public", name: "guard_items", securityDefiner: false }
          })
        ]
      }),
      table({ name: "item_history" }),
      table({
        name: "other",
        triggers: [
          trigger({
            name: "other_guard",
            events: ["INSERT"],
            function: { schema: "public", name: "broken_fn", securityDefiner: false }
          })
        ]
      })
    ],
    functions
  });
  const html = renderHtml(d, { tags });
  const update = cell(html, "items", "UPDATE");

  it("shows the guard (condition → error), comment, side effects and columns of the trigger function", () => {
    assert.ok(update.includes("Guards (condition → error)"));
    assert.ok(update.includes("locked items cannot be updated"));
    assert.ok(update.includes("check_violation"));
    assert.ok(update.includes("Locked rows cannot change"));
    assert.ok(update.includes(`<a href="#${anchorId("t", "item_history")}">public.item_history</a>`));
    assert.ok(update.includes("Referenced columns"));
    assert.ok(update.includes("Full definition of guard_items()"));
    assert.ok(update.includes("the full definition is authoritative"));
  });

  it("shows guards found in called helpers labelled with the via chain, linking to their details", () => {
    assert.ok(update.includes("Rules found in called functions"));
    const via = update.indexOf("via ");
    assert.ok(via >= 0);
    const helper = update.slice(via);
    assert.ok(helper.includes(`href="#${anchorId("fn", "check_owner", "1")}">check_owner()</a>`));
    assert.ok(helper.includes("only the owner may change the item"));
    assert.ok(helper.includes("check_owner()</a> → <a"));
    assert.ok(helper.includes("is_owner()"));
  });

  it("shows the same rules in the function detail", () => {
    const start = html.indexOf(`id="${anchorId("fn", "guard_items", "0")}"`);
    const detail = html.slice(start, html.indexOf("</article>", start));
    assert.ok(detail.includes("locked items cannot be updated"));
    assert.ok(detail.includes("via "));
  });

  it("falls back to the original definition when a body cannot be analyzed", () => {
    const insert = cell(html, "other", "INSERT");
    assert.ok(insert.includes(">failed<"));
    assert.ok(insert.includes("Full definition of broken_fn()"));
    assert.ok(insert.includes("unclosed"));
  });

  it("escapes markup coming from function bodies and RAISE messages", () => {
    const evil = doc({
      tables: [
        table({
          name: "t",
          triggers: [
            trigger({
              name: "g",
              events: ["INSERT"],
              function: { schema: "public", name: "evil", securityDefiner: false }
            })
          ]
        })
      ],
      functions: [
        fn(
          "evil",
          `
-- ${META}
BEGIN
  IF NEW.x = '${META}' THEN
    RAISE EXCEPTION '${META}' USING HINT = '${META}';
  END IF;
  INSERT INTO "${META}" VALUES (1);
  RETURN NEW;
END;`,
          { comment: META }
        )
      ]
    });
    const out = renderHtml(evil, { tags });
    assert.ok(!/<meta http-equiv=refresh/i.test(out));
    assert.ok(out.includes("&lt;meta http-equiv=refresh"));
    assert.equal((out.match(/<meta[\s>]/gi) ?? []).length, 4);
  });
});

describe("redaction of text taken from function bodies", () => {
  const body = `
-- calls ${pgUrl({ user: "svc", password: "pw", host: "db.internal", port: 5432 })} with ${JWT}
BEGIN
  IF NEW.token = '${JWT}' THEN
    RAISE EXCEPTION 'bad key ${JWT}' USING DETAIL = 'sk-abcdefghijklmnopqrstuvwxyz';
  END IF;
  RETURN NEW;
END;`;

  it("redacts the analysis computed at extract time", () => {
    const raw: RawCatalog = {
      schema: "public",
      serverVersion: "17",
      now: new Date(0),
      roles: [],
      tables: [],
      columns: [],
      policies: [],
      triggers: [],
      constraints: [],
      tableGrants: [],
      columnGrants: [],
      views: [],
      functions: [
        {
          name: "f",
          identity_arguments: "",
          returns: "trigger",
          prokind: "f",
          language: "plpgsql",
          volatility: "v",
          security_definer: false,
          search_path: "",
          anon_execute: false,
          authenticated_execute: true,
          definition: def("f", body),
          comment: `COMMENT with ${JWT}`
        }
      ],
      extensionOwnedFunctions: 0,
      extensionOwnedRelations: 0,
      eventTriggers: []
    };
    // extractRules applies redactDeep to the assembled document; reproduce that here
    const out = JSON.stringify(redactDeep(assembleDocument(raw)));
    const analysis = redactDeep(assembleDocument(raw)).functions[0]?.analysis;
    assert.equal(analysis?.guards.length, 1);
    assert.ok(analysis?.guards[0]?.message?.includes("[REDACTED]"));
    assert.ok(!out.includes(JWT));
    assert.ok(!out.includes("postgresql://"));
    assert.ok(!out.includes("sk-abcdefghijklmnopqrstuvwxyz"));
  });

  it("redacts a pre-supplied analysis at render time", () => {
    const f = fn("f", "BEGIN RETURN NEW; END;");
    f.analysis = analyzeFunction({ ...f, definition: def("f", body) }, "public", new Set(["f"]));
    assert.ok(JSON.stringify(f.analysis).includes(JWT));
    const out = renderHtml(
      doc({
        tables: [
          table({
            name: "t",
            triggers: [trigger({ name: "g", function: { schema: "public", name: "f", securityDefiner: false } })]
          })
        ],
        functions: [f]
      }),
      { tags }
    );
    assert.ok(!out.includes(JWT));
    assert.ok(!out.includes("sk-abcdefghijklmnopqrstuvwxyz"));
    assert.ok(out.includes("bad key [REDACTED]"));
  });
});

describe("assertRulesDocument with function analysis", () => {
  const base = () => doc({ functions: [fn("f", "BEGIN RETURN NEW; END;")] });

  it("accepts functions with and without analysis", () => {
    const d = base();
    assertRulesDocument(d);
    const f = d.functions[0] as FunctionInfo;
    f.analysis = analyzeFunction(f, "public", new Set(["f"]));
    assertRulesDocument(d);
    assert.deepEqual(validate(loadRulesSchema(), d), []);
  });

  it("rejects a malformed analysis", () => {
    const d = base();
    (d.functions[0] as unknown as Record<string, unknown>).analysis = { status: "<b>", guards: [] };
    assert.throws(() => assertRulesDocument(d), RulesDocumentError);
    (d.functions[0] as unknown as Record<string, unknown>).analysis = {
      ...analyzeFunction(d.functions[0] as FunctionInfo, "public", new Set()),
      guards: [{ path: "x" }]
    };
    assert.throws(() => assertRulesDocument(d), RulesDocumentError);
  });
});

describe("overloaded functions", () => {
  const helperA = fn("is_in_ws", "BEGIN RETURN true; END;", { identityArguments: "id uuid", returns: "boolean" });
  const helperB = fn("is_in_ws", "BEGIN RETURN false; END;", {
    identityArguments: "id uuid, team uuid",
    returns: "boolean"
  });
  const root = fn("trg", "BEGIN IF NOT public.is_in_ws(NEW.id) THEN RAISE EXCEPTION 'no'; END IF; RETURN NEW; END;");
  const html = renderHtml(
    doc({
      tables: [
        table({
          name: "t",
          triggers: [
            trigger({
              name: "g",
              events: ["INSERT"],
              function: { schema: "public", name: "trg", securityDefiner: false }
            })
          ]
        })
      ],
      functions: [root, helperA, helperB]
    }),
    { tags }
  );

  it("notes on the other overloads that rules are shown for one overload only", () => {
    const article = (i: number) => {
      const start = html.indexOf(`id="${anchorId("fn", "is_in_ws", String(i))}"`);
      return html.slice(start, html.indexOf("</article>", start));
    };
    assert.ok(!article(1).includes("Rules are shown for only one overload"));
    assert.ok(article(1).includes("Rules in"));
    assert.ok(article(2).includes("Rules are shown for only one overload with this name"));
    assert.ok(!article(2).includes("Rules in"));
  });

  it("marks a via link whose name resolves to several overloads", () => {
    const insert = cell(html, "t", "INSERT");
    const via = insert.slice(insert.indexOf("via "));
    assert.ok(via.includes('is_in_ws()</a> <span class="badge warn">overloaded</span>'));
  });
});

describe("assertRulesDocument with a crafted analysis", () => {
  const withAnalysis = (mutate: (a: Record<string, unknown>) => void) => {
    const d = doc({ functions: [fn("f", "BEGIN IF x THEN RAISE EXCEPTION 'm'; END IF; RETURN NEW; END;")] });
    const f = d.functions[0] as FunctionInfo;
    const a = structuredClone(analyzeFunction(f, "public", new Set(["f"]))) as unknown as Record<string, unknown>;
    mutate(a);
    (f as unknown as Record<string, unknown>).analysis = a;
    return d;
  };
  const guard = (a: Record<string, unknown>) => (a.guards as Record<string, unknown>[])[0] as Record<string, unknown>;
  const element = (a: Record<string, unknown>) =>
    (guard(a).path as Record<string, unknown>[])[0] as Record<string, unknown>;

  const cases: [string, (a: Record<string, unknown>) => void][] = [
    ["notTaken is a string", (a) => (element(a).notTaken = "abc")],
    ["notTaken holds a number", (a) => (element(a).notTaken = [1])],
    ["a path element is a number", (a) => (guard(a).path = [5])],
    ["kind is not a string", (a) => (element(a).kind = 1)],
    ["sql is an object", (a) => (element(a).sql = {})],
    ["message is a number", (a) => (guard(a).message = 3)],
    ["statement is missing", (a) => delete guard(a).statement],
    ["a side effect name is not a string", (a) => (a.sideEffects = [{ operation: "INSERT", schema: null, name: 1 }])],
    ["a column list holds a number", (a) => (a.newColumns = [1])],
    ["an early return path element is null", (a) => (a.earlyReturns = [{ path: [null], statement: "RETURN" }])],
    ["unparsedCount is a string", (a) => (a.unparsedCount = "1")]
  ];
  for (const [label, mutate] of cases) {
    it(`throws RulesDocumentError (not TypeError) when ${label}`, () => {
      assert.throws(() => assertRulesDocument(withAnalysis(mutate)), RulesDocumentError);
    });
  }

  it("still accepts the analysis it produces itself", () => {
    const d = withAnalysis(() => {});
    assertRulesDocument(d);
    assert.deepEqual(validate(loadRulesSchema(), d), []);
  });
});
