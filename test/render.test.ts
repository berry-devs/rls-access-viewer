import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { join } from "node:path";
import { describe, it } from "node:test";
import { compileTags, ConfigError, loadConfig, matchTags, parseConfig } from "../src/model/config.ts";
import { DECODE_HASH_SOURCE, SCRIPT, STYLE } from "../src/render/assets.ts";
import { anchorId, jsonForScript, renderHtml } from "../src/render/html.ts";
import { defaultGrants, doc, pgUrl, policy, table, trigger, TEAM_ROLE } from "./fixtures.ts";
import { loadRulesSchema, validate } from "../src/model/schema.ts";
import { assertRulesDocument, RulesDocumentError } from "../src/model/validate.ts";

const tags = compileTags(loadConfig());
const JWT = "eyJhbGciOiJIUzI1NiJ9.eyJyb2xlIjoic2VydmljZV9yb2xlIn0.c2lnbmF0dXJlX3NpZ25hdHVyZQ";
const MFA = "((auth.jwt() ->> 'aal'::text) = 'aal2'::text)";

/** Cuts the element with the given id up to the next </section>. */
function section(html: string, id: string): string {
  const start = html.indexOf(`id="${id}"`);
  assert.ok(start >= 0, `section ${id} not found`);
  return html.slice(start, html.indexOf("</section>", start));
}

const evil = "x</script><img src=x onerror=alert(1)>";
const fixture = doc({
  tables: [
    table({
      name: "tags",
      policies: [
        policy({ name: "all access", command: "ALL", using: TEAM_ROLE }),
        policy({ name: "mfa", command: "ALL", permissive: false, using: MFA }),
        policy({ name: "broken", command: "SELECT", using: "((a = 1) AND (b = 2)" }),
        policy({ name: "own", command: "UPDATE", using: "((created_by = auth.uid()) AND (deleted IS FALSE))" })
      ],
      triggers: [
        trigger({
          name: "guard",
          events: ["INSERT", "UPDATE"],
          when: "(new.status <> old.status)",
          updateColumns: ["status"]
        })
      ]
    }),
    table({ name: "open_table", rls: { enabled: false, forced: false } }),
    table({ name: evil, policies: [policy({ name: evil, command: "SELECT", using: `name = '${evil}'` })] })
  ],
  views: [
    {
      name: "v_ok",
      kind: "view",
      securityInvoker: true,
      securityBarrier: false,
      definition: "SELECT 1",
      baseRelations: [],
      grants: []
    },
    {
      name: "v_definer",
      kind: "view",
      securityInvoker: false,
      securityBarrier: false,
      definition: "SELECT 1",
      baseRelations: [],
      grants: []
    }
  ],
  functions: [
    {
      name: "get_team_ids_for_roles",
      identityArguments: "roles team_role[]",
      returns: "SETOF uuid",
      kind: "function",
      language: "sql",
      volatility: "STABLE",
      securityDefiner: true,
      searchPath: null,
      executableBy: { anon: true, authenticated: true },
      definition: `CREATE FUNCTION ... AS $$ select net.http_post('${pgUrl({ user: "postgres", password: "pw", port: 54322 })}', '${JWT}') $$`
    }
  ]
});

describe("renderHtml", () => {
  const html = renderHtml(fixture, { tags });

  it("shows an ALL policy in all four operation cells, marked as from ALL", () => {
    for (const op of ["SELECT", "INSERT", "UPDATE", "DELETE"]) {
      const s = section(html, anchorId("c", "tags", op));
      assert.ok(s.includes("all access"), op);
      assert.ok(s.includes("from ALL"), op);
    }
  });

  it("lists what is not covered in the reference tab without claiming that Storage is out of scope", () => {
    const s = section(html, "tab-meta");
    assert.ok(s.includes("<h3>Not covered</h3>"));
    assert.ok(s.includes("The cron schema is not covered."));
    assert.ok(s.includes("Of the storage schema only storage.objects and the settings of storage.buckets are covered"));
    assert.ok(!/\bv1\b/.test(s));
  });

  it("composes RESTRICTIVE policies with AND", () => {
    const s = section(html, anchorId("c", "tags", "SELECT"));
    assert.ok(s.includes("RESTRICTIVE (all must pass = AND)"));
    assert.ok(s.includes("PERMISSIVE (any one passes = OR)"));
    assert.ok(s.includes("MFA (aal2)"));
  });

  it("labels roles without PERMISSIVE policies as denied by default and service_role as bypassing RLS", () => {
    const s = section(html, anchorId("c", "tags", "SELECT"));
    assert.ok(s.includes("denied by default")); // anon
    assert.ok(s.includes("bypasses RLS"));
  });

  it("separates UPDATE USING (target rows) from WITH CHECK (new rows) and flags the reuse of USING", () => {
    const s = section(html, anchorId("c", "tags", "UPDATE"));
    assert.ok(s.includes("USING (target rows)"));
    assert.ok(s.includes("WITH CHECK (new rows)"));
    assert.ok(s.includes("the USING expression is reused"));
    assert.ok(s.includes("own rows"));
    assert.ok(s.includes("excludes soft-deleted"));
  });

  it("orders evaluation as BEFORE, WITH CHECK, constraints, AFTER and shows trigger attributes", () => {
    const s = section(html, anchorId("c", "tags", "INSERT"));
    const order = ["BEFORE triggers", "WITH CHECK</b>", "Constraints</b>", "AFTER triggers"].map((k) => s.indexOf(k));
    assert.ok(
      order.every((i) => i >= 0),
      String(order)
    );
    assert.deepEqual(
      [...order].sort((a, b) => a - b),
      order
    );
    assert.ok(s.includes("guard"));
    assert.ok(s.includes("INSERT | UPDATE"));
    assert.ok(s.includes("UPDATE OF: status"));
    assert.ok(s.includes("WHEN:"));
    assert.ok(s.includes("FOR EACH ROW"));
  });

  it("shows expressions it cannot split as the original SQL", () => {
    const s = section(html, anchorId("c", "tags", "SELECT"));
    assert.ok(s.includes("could not split; original SQL"));
    assert.ok(s.includes('b = <span class="n">2</span>'));
  });

  it("warns about RLS-disabled tables, views without security_invoker and risky SECURITY DEFINER functions", () => {
    assert.ok(html.includes('class="row-danger"'));
    assert.ok(section(html, anchorId("c", "open_table", "SELECT")).includes("RLS is disabled"));
    assert.ok(html.includes("security_invoker not set"));
    assert.ok(html.includes("search_path not set"));
    assert.ok(html.includes("executable by anon"));
    assert.ok(html.includes("Tables with RLS disabled: 1"));
    assert.ok(html.includes("Views that may bypass RLS: 1"));
  });

  it("links helper functions called by policies to their definitions", () => {
    assert.ok(html.includes(`<a class="f" href="#${anchorId("fn", "get_team_ids_for_roles", "0")}">`));
    assert.ok(html.includes(`id="${anchorId("fn", "get_team_ids_for_roles", "0")}"`));
  });

  it("escapes names and definitions so that </script> cannot break out of the embedded JSON", () => {
    assert.ok(!html.includes("<img src=x"));
    const scripts = html.match(/<script[\s>]/g) ?? [];
    assert.equal(scripts.length, 2); // the embedded JSON and the viewer script only
    const json = html.slice(
      html.indexOf('id="rules-json">'),
      html.indexOf("</script>", html.indexOf('id="rules-json">'))
    );
    assert.ok(!json.includes("<"));
    assert.ok(json.includes("\\u003c/script\\u003e"));
  });

  it("never outputs connection strings or JWTs found in function bodies", () => {
    assert.ok(!html.includes("postgresql://"));
    assert.ok(!html.includes(JWT));
    assert.ok(!/eyJ[A-Za-z0-9_-]{8,}\./.test(html));
    assert.ok(html.includes("[REDACTED]"));
  });

  it("allows only the hashes of the inline STYLE / SCRIPT in the CSP", () => {
    const hash = (s: string) => createHash("sha256").update(s).digest("base64");
    assert.ok(html.includes(`script-src 'sha256-${hash(SCRIPT)}'`));
    assert.ok(html.includes(`style-src 'sha256-${hash(STYLE)}'`));
    assert.ok(html.includes("default-src 'none'"));
    // Drop quoted attribute values first: escaped text inside them may legitimately contain " onerror="
    const markup = html.replace(/"[^"]*"/g, '""');
    assert.ok(!/<[^>]*\son[a-z]+=/i.test(markup));
    assert.ok(!/<[^>]*\sstyle=/i.test(markup));
  });

  it("produces documents that conform to schemas/rules.schema.json", () => {
    assert.deepEqual(validate(loadRulesSchema(), fixture), []);
    assert.notDeepEqual(validate(loadRulesSchema(), { ...fixture, formatVersion: 2 }), []);
  });
});

describe("renderHtml without TRUNCATE", () => {
  const html = renderHtml(
    doc({
      tables: [
        table({
          name: "audit",
          triggers: [trigger({ name: "wipe_guard", events: ["TRUNCATE"], timing: "BEFORE", level: "STATEMENT" })],
          grants: defaultGrants().filter((g) => g.privilege !== "TRUNCATE")
        }),
        table({
          name: "restricted",
          grants: defaultGrants().filter((g) => !(g.grantee === "anon" && g.privilege === "DELETE"))
        })
      ]
    }),
    { tags }
  ).replace(/<script type="application\/json" id="rules-json">.*?<\/script>/s, ""); // rules.json keeps them

  it("has no TRUNCATE column, cell detail or note", () => {
    assert.ok(!html.includes("<th>TRUNCATE</th>"));
    assert.ok(!html.includes(`id="${anchorId("c", "audit", "TRUNCATE")}"`));
    assert.ok(!html.includes("not subject to RLS"));
  });

  it("does not show TRUNCATE-only triggers", () => {
    assert.ok(!html.includes("wipe_guard"));
  });

  /** Cuts the GRANTs <details> of a table. */
  const grantsOf = (name: string) => {
    const start = html.indexOf("<summary>GRANTs", html.indexOf(`id="${anchorId("t", name)}"`));
    return html.slice(start, html.indexOf("</details>", start));
  };

  it("treats a revoked TRUNCATE as the Supabase default", () => {
    assert.ok(!grantsOf("audit").includes("revoked from default"));
    assert.ok(grantsOf("audit").includes("Same as the Supabase default"));
  });

  it("notes that TRUNCATE is not compared, with or without a difference", () => {
    assert.ok(grantsOf("restricted").includes("revoked from default"));
    for (const name of ["audit", "restricted"]) assert.ok(grantsOf(name).includes("TRUNCATE is not compared"), name);
  });
});

describe("renderHtml with omitted policy expressions", () => {
  const html = renderHtml(
    doc({
      tables: [
        table({
          name: "omit",
          policies: [
            policy({ name: "sel_no_using", command: "SELECT" }),
            policy({ name: "ins_no_check", command: "INSERT" }),
            policy({ name: "restr_no_using", command: "DELETE", permissive: false }),
            policy({ name: "del", command: "DELETE", using: "(v > 0)" })
          ]
        })
      ]
    }),
    { tags }
  );

  it("labels an omitted expression by its effect instead of showing it as a condition", () => {
    const select = section(html, anchorId("c", "omit", "SELECT"));
    assert.ok(select.includes('USING omitted</span> <span class="muted">this policy grants no rows'));
    assert.ok(select.includes("The PERMISSIVE policies that apply omit the expression this operation needs"));
    assert.ok(!select.includes("(none)"));
    const insert = section(html, anchorId("c", "omit", "INSERT"));
    assert.ok(insert.includes('WITH CHECK omitted</span> <span class="muted">this policy allows no rows'));
    const del = section(html, anchorId("c", "omit", "DELETE"));
    assert.ok(del.includes("no restriction from this policy"));
    assert.ok(!/\btrue\b[^<]*omitted/.test(select + insert + del));
  });
});

describe("renderHtml with a crafted rules.json", () => {
  const META = "<meta http-equiv=refresh content=0;url=https://attacker.example>";
  // renderHtml is called directly (bypassing assertRulesDocument), so feed markup through enum-like and numeric fields
  const crafted = doc({
    tables: [
      table({
        name: "parent",
        columns: [{ name: "id", type: "int", notNull: true, default: null, identity: META as never, generated: false }],
        triggers: [trigger({ name: "t", timing: META as never, events: [META as never] })],
        constraints: [{ kind: META as never, name: "c", columns: [], definition: "x" }]
      }),
      table({
        name: "child",
        constraints: [
          {
            kind: "foreign",
            name: "child_parent",
            columns: ["parent_id"],
            references: { schema: "public", table: "parent", columns: ["id"] },
            onDelete: META as never,
            onUpdate: META as never,
            definition: "FOREIGN KEY (parent_id) REFERENCES parent(id)"
          }
        ]
      })
    ],
    functions: [
      {
        name: "f",
        identityArguments: "",
        returns: "void",
        kind: "function",
        language: "sql",
        volatility: META as never,
        securityDefiner: false,
        searchPath: null,
        executableBy: { anon: false, authenticated: true },
        definition: null
      }
    ],
    externalForeignKeys: [
      {
        kind: "foreign",
        name: "ext",
        columns: ["parent_id"],
        references: { schema: "public", table: "parent", columns: ["id"] },
        onDelete: META as never,
        onUpdate: META as never,
        definition: "x",
        from: { schema: "other", table: "t" }
      }
    ],
    excluded: { extensionOwnedFunctions: META as never, extensionOwnedRelations: META as never, eventTriggers: [] }
  });

  it("escapes every interpolated field so no injected tag reaches the output", () => {
    const html = renderHtml(crafted, { tags });
    assert.ok(!/<meta http-equiv=refresh/i.test(html));
    assert.equal((html.match(/<meta[\s>]/gi) ?? []).length, 4); // charset, viewport, CSP, referrer
    assert.ok(html.includes("&lt;meta http-equiv=refresh"));
    assert.ok(html.includes("Functions owned by extensions: ?"));
  });
});

describe("schema validation of crafted keys", () => {
  const withSourceKey = (key: string) => {
    // Built through JSON.parse so that "__proto__" becomes an own property, as it would in a crafted file
    const json = JSON.stringify(doc()).replace('"source":{', `"source":{${JSON.stringify(key)}:1,`);
    return JSON.parse(json) as unknown;
  };

  it("rejects Object.prototype member names as unknown properties", () => {
    for (const key of ["constructor", "toString", "hasOwnProperty", "valueOf", "__proto__"]) {
      const d = withSourceKey(key);
      assert.ok(Object.hasOwn((d as { source: object }).source, key), key);
      const errors = validate(loadRulesSchema(), d);
      assert.ok(
        errors.includes(`$.source: unexpected property ${JSON.stringify(key)}`),
        `${key}: ${errors.join("; ")}`
      );
      assert.throws(() => assertRulesDocument(d), RulesDocumentError, key);
    }
  });

  it("escapes control characters of unknown keys in the error message", () => {
    const d = withSourceKey("\u001b[31mred");
    const errors = validate(loadRulesSchema(), d).join("; ");
    assert.ok(!errors.includes("\u001b"));
    assert.ok(errors.includes("\\u001b[31mred"));
    assert.throws(
      () => assertRulesDocument(d),
      (e: unknown) => e instanceof RulesDocumentError && !e.message.includes("\u001b")
    );
  });
});

describe("tag configs", () => {
  it("rejects a non-string description as a ConfigError", () => {
    const tag = { id: "x", label: "x", pattern: "x" };
    assert.throws(() => parseConfig({ tags: [{ ...tag, description: 1 }] }), ConfigError);
    assert.throws(
      () => parseConfig({ tags: [{ ...tag, description: { text: "x" } }] }),
      /tags\[0\]\.description must be a string/
    );
    assert.equal(parseConfig({ tags: [{ ...tag, description: "ok" }] }).tags[0]?.description, "ok");
    assert.equal(parseConfig({ tags: [tag] }).tags[0]?.description, undefined);
  });

  it("loads the bundled default and a custom config file, which replaces the defaults", () => {
    const custom = compileTags(loadConfig(join(import.meta.dirname, "custom-tags.config.json")));
    assert.deepEqual(
      matchTags("(tenant_id IN ( SELECT current_tenant_ids() AS current_tenant_ids))", custom).map((t) => t.id),
      ["tenant"]
    );
    assert.equal(
      custom.find((t) => t.id === "tenant")?.description,
      "Limits rows to the tenants of the signed-in user"
    );
    assert.deepEqual(
      matchTags("(SELECT IS_ADMIN FROM members)", custom).map((t) => t.id),
      ["admin-flag"]
    );
    assert.deepEqual(
      matchTags("true", custom).map((t) => t.id),
      []
    );
    assert.deepEqual(
      matchTags("true", tags).map((t) => t.id),
      ["always"]
    );
  });
});

describe("jsonForScript", () => {
  it("escapes < > & and line separators and still round-trips through JSON.parse", () => {
    const value = { s: "</script><!-- & \u2028\u2029" };
    const out = jsonForScript(value);
    assert.ok(!/[<>&\u2028\u2029]/.test(out));
    assert.deepEqual(JSON.parse(out), value);
  });
});

describe("anchorId", () => {
  it("encodes non-alphanumeric characters without collisions", () => {
    assert.notEqual(anchorId("t", "a-b"), anchorId("t", "a.b"));
    assert.match(anchorId("c", 'x"<y', "SELECT"), /^[A-Za-z0-9_.-]+$/);
  });
});

describe("viewer script decodeHash", () => {
  const decodeHash = new Function(`${DECODE_HASH_SOURCE}; return decodeHash;`)() as (hash: string) => string;

  it("decodes a percent-encoded hash", () => {
    assert.equal(decodeHash("#c--a.20b"), "c--a.20b");
    assert.equal(decodeHash("#tab%2Dmatrix"), "tab-matrix");
    assert.equal(decodeHash(""), "");
  });

  it("falls back to the raw text instead of throwing on a malformed hash", () => {
    assert.equal(decodeHash("#%"), "%");
    assert.equal(decodeHash("#%E0%A4%A"), "%E0%A4%A");
  });

  it("is the decoder the viewer script actually uses", () => {
    assert.ok(SCRIPT.includes(DECODE_HASH_SOURCE));
    assert.ok(SCRIPT.includes("decodeHash(location.hash)"));
    assert.ok(!SCRIPT.includes("decodeURIComponent(location.hash"));
  });
});
