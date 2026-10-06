import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { assembleDocument, decodeTriggerType, extractTriggerWhen, type RawCatalog } from "../src/extract/index.ts";

describe("decodeTriggerType (tgtype bits)", () => {
  it("splits a BEFORE ROW INSERT|UPDATE trigger into both events", () => {
    // ROW(1) | BEFORE(2) | INSERT(4) | UPDATE(16)
    assert.deepEqual(decodeTriggerType(1 | 2 | 4 | 16), {
      timing: "BEFORE",
      level: "ROW",
      events: ["INSERT", "UPDATE"]
    });
  });

  it("decodes an AFTER statement-level TRUNCATE", () => {
    assert.deepEqual(decodeTriggerType(32), { timing: "AFTER", level: "STATEMENT", events: ["TRUNCATE"] });
  });

  it("decodes INSTEAD OF DELETE", () => {
    assert.deepEqual(decodeTriggerType(1 | 64 | 8), { timing: "INSTEAD OF", level: "ROW", events: ["DELETE"] });
  });

  it("picks up INSERT|UPDATE|DELETE together", () => {
    assert.deepEqual(decodeTriggerType(1 | 4 | 8 | 16).events, ["INSERT", "UPDATE", "DELETE"]);
  });
});

describe("extractTriggerWhen", () => {
  it("extracts only the WHEN condition, honouring parentheses and quotes", () => {
    const def =
      "CREATE TRIGGER t BEFORE UPDATE OF status ON public.x FOR EACH ROW WHEN (((old.status)::text IS DISTINCT FROM 'a)b'::text)) EXECUTE FUNCTION f()";
    assert.equal(extractTriggerWhen(def), "((old.status)::text IS DISTINCT FROM 'a)b'::text)");
  });

  it("returns null without WHEN", () => {
    assert.equal(
      extractTriggerWhen("CREATE TRIGGER t AFTER INSERT ON public.x FOR EACH ROW EXECUTE FUNCTION f()"),
      null
    );
  });
});

function raw(partial: Partial<RawCatalog>): RawCatalog {
  return {
    schema: "public",
    serverVersion: "17.6",
    now: new Date("2026-10-01T00:00:00Z"),
    roles: [],
    tables: [],
    columns: [],
    policies: [],
    triggers: [],
    constraints: [],
    tableGrants: [],
    columnGrants: [],
    views: [],
    functions: [],
    extensionOwnedFunctions: 0,
    extensionOwnedRelations: 0,
    eventTriggers: [],
    ...partial
  };
}

describe("assembleDocument", () => {
  it("maps polcmd and FK action codes to names", () => {
    const d = assembleDocument(
      raw({
        tables: [{ name: "a", relkind: "r", rls_enabled: true, rls_forced: false, is_partition: false }],
        policies: [
          {
            table_name: "a",
            name: "p1",
            cmd: "*",
            permissive: true,
            roles: ["authenticated"],
            using_expr: "true",
            with_check_expr: null
          },
          {
            table_name: "a",
            name: "p2",
            cmd: "w",
            permissive: false,
            roles: ["public"],
            using_expr: null,
            with_check_expr: "x"
          }
        ],
        constraints: [
          {
            name: "a_b_fkey",
            contype: "f",
            table_schema: "public",
            table_name: "a",
            definition: "FOREIGN KEY ...",
            columns: ["b_id"],
            ref_schema: "public",
            ref_table: "b",
            ref_columns: ["id"],
            on_delete: "c",
            on_update: "n"
          },
          {
            name: "ext_fkey",
            contype: "f",
            table_schema: "other",
            table_name: "z",
            definition: "FOREIGN KEY ...",
            columns: ["a_id"],
            ref_schema: "public",
            ref_table: "a",
            ref_columns: ["id"],
            on_delete: "r",
            on_update: "a"
          }
        ]
      })
    );
    const t = d.tables[0];
    assert.deepEqual(
      t?.policies.map((p) => [p.command, p.permissive]),
      [
        ["ALL", true],
        ["UPDATE", false]
      ]
    );
    const fk = t?.constraints[0];
    assert.equal(fk?.kind, "foreign");
    if (fk?.kind === "foreign") {
      assert.equal(fk.onDelete, "CASCADE");
      assert.equal(fk.onUpdate, "SET NULL");
    }
    assert.equal(d.externalForeignKeys.length, 1);
    assert.equal(d.externalForeignKeys[0]?.onDelete, "RESTRICT");
  });

  it("moves platform- and extension-owned event triggers to excluded", () => {
    const d = assembleDocument(
      raw({
        eventTriggers: [
          { name: "pgrst_ddl_watch", owner: "supabase_admin", extension_owned: false },
          { name: "graphql_watch_ddl", owner: "supabase_admin", extension_owned: true },
          { name: "my_ddl_guard", owner: "postgres", extension_owned: false }
        ],
        extensionOwnedFunctions: 143
      })
    );
    assert.deepEqual(
      d.excluded.eventTriggers.map((e) => e.name),
      ["pgrst_ddl_watch", "graphql_watch_ddl"]
    );
    assert.deepEqual(d.eventTriggers, [{ name: "my_ddl_guard", owner: "postgres" }]);
    assert.equal(d.excluded.extensionOwnedFunctions, 143);
  });

  it("groups column-level GRANTs by (role, privilege)", () => {
    const d = assembleDocument(
      raw({
        tables: [{ name: "a", relkind: "r", rls_enabled: true, rls_forced: false, is_partition: false }],
        columnGrants: [
          { table_name: "a", column_name: "x", grantee: "authenticated", privilege: "UPDATE" },
          { table_name: "a", column_name: "y", grantee: "authenticated", privilege: "UPDATE" }
        ]
      })
    );
    assert.deepEqual(d.tables[0]?.grants, [{ grantee: "authenticated", privilege: "UPDATE", columns: ["x", "y"] }]);
  });

  it("reports searchPath=null for functions without search_path", () => {
    const d = assembleDocument(
      raw({
        functions: [
          {
            name: "f",
            identity_arguments: "",
            returns: "void",
            prokind: "f",
            language: "plpgsql",
            volatility: "v",
            security_definer: true,
            search_path: null,
            anon_execute: true,
            authenticated_execute: true,
            definition: "CREATE FUNCTION ..."
          }
        ]
      })
    );
    assert.equal(d.functions[0]?.searchPath, null);
    assert.equal(d.functions[0]?.executableBy.anon, true);
  });
});
