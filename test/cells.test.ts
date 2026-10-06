import assert from "node:assert/strict";
import { describe, it } from "node:test";
import {
  buildCell,
  buildReverseFkIndex,
  cascadeEffects,
  composeForRole,
  countCascadeNodes,
  grantDiffs,
  policiesForOperation
} from "../src/model/cells.ts";
import { OPERATIONS, type ForeignKeyConstraint } from "../src/model/types.ts";
import { defaultGrants, doc, policy, table, trigger, TEAM_ROLE } from "./fixtures.ts";

const fk = (
  name: string,
  refTable: string,
  onDelete: ForeignKeyConstraint["onDelete"],
  onUpdate: ForeignKeyConstraint["onUpdate"] = "NO ACTION"
): ForeignKeyConstraint => ({
  kind: "foreign",
  name,
  columns: [`${refTable}_id`],
  references: { schema: "public", table: refTable, columns: ["id"] },
  onDelete,
  onUpdate,
  definition: `FOREIGN KEY (${refTable}_id) REFERENCES ${refTable}(id)`
});

describe("cmd=ALL expansion", () => {
  const t = table({
    name: "tags",
    policies: [policy({ name: "all", command: "ALL", using: TEAM_ROLE })]
  });

  it("appears in all four operations, marked as coming from ALL", () => {
    for (const op of OPERATIONS) {
      const cps = policiesForOperation(t, op);
      assert.equal(cps.length, 1, op);
      assert.equal(cps[0]?.fromAll, true, op);
    }
  });

  it("reuses USING for new rows of INSERT / UPDATE when WITH CHECK is absent", () => {
    const ins = policiesForOperation(t, "INSERT")[0];
    assert.equal(ins?.withCheck, TEAM_ROLE);
    assert.equal(ins?.withCheckFromUsing, true);
    assert.equal(ins?.using, null);
    const upd = policiesForOperation(t, "UPDATE")[0];
    assert.equal(upd?.using, TEAM_ROLE);
    assert.equal(upd?.withCheck, TEAM_ROLE);
    assert.equal(upd?.withCheckFromUsing, true);
  });

  it("keeps operation-specific policies out of other operations", () => {
    const t2 = table({ name: "x", policies: [policy({ name: "sel", command: "SELECT", using: "true" })] });
    assert.equal(policiesForOperation(t2, "SELECT").length, 1);
    assert.equal(policiesForOperation(t2, "DELETE").length, 0);
  });
});

describe("per-role composition", () => {
  const t = table({
    name: "team_member_roles",
    policies: [
      policy({ name: "own", command: "SELECT", using: "(employee_id = auth.uid())" }),
      policy({ name: "reporting", command: "SELECT", roles: ["reporting_role"], using: "true" }),
      policy({ name: "mfa", command: "SELECT", permissive: false, using: "( SELECT mfa_verified() AS mfa_verified)" }),
      policy({ name: "ip", command: "SELECT", permissive: false, using: "( SELECT ip_verified() AS ip_verified)" }),
      policy({ name: "pub", command: "INSERT", roles: ["public"], withCheck: "true" })
    ]
  });
  const d = doc({ tables: [t] });

  it("collects the RESTRICTIVE policies of the role on the AND side", () => {
    const auth = composeForRole(d, t, "SELECT", "authenticated");
    assert.deepEqual(
      auth.permissive.map((p) => p.policy.name),
      ["own"]
    );
    assert.deepEqual(
      auth.restrictive.map((p) => p.policy.name),
      ["mfa", "ip"]
    );
    assert.equal(auth.deniedByDefault, false);
  });

  it("does not OR another role's PERMISSIVE policy (reporting_role's true) into authenticated", () => {
    const reporting = composeForRole(d, t, "SELECT", "reporting_role");
    assert.deepEqual(
      reporting.permissive.map((p) => p.policy.name),
      ["reporting"]
    );
    assert.equal(reporting.restrictive.length, 0);
  });

  it("denies by default when no PERMISSIVE policy applies to the role", () => {
    assert.equal(composeForRole(d, t, "SELECT", "anon").deniedByDefault, true);
    assert.equal(composeForRole(d, t, "DELETE", "authenticated").deniedByDefault, true);
  });

  it("applies roles=public policies to every role", () => {
    assert.equal(composeForRole(d, t, "INSERT", "anon").permissive.length, 1);
    assert.equal(composeForRole(d, t, "INSERT", "authenticated").permissive.length, 1);
  });

  it("treats service_role as BYPASSRLS and never denies it by default", () => {
    const sr = composeForRole(d, t, "DELETE", "service_role");
    assert.equal(sr.bypassRls, true);
    assert.equal(sr.deniedByDefault, false);
  });

  it("reports hasGrant=false for a role without the privilege", () => {
    const t2 = table({ name: "y", grants: defaultGrants(["authenticated"]) });
    assert.equal(composeForRole(doc({ tables: [t2] }), t2, "SELECT", "anon").hasGrant, false);
  });

  it("does not deny by default when RLS is disabled (only GRANTs apply)", () => {
    const t2 = table({ name: "z", rls: { enabled: false, forced: false } });
    assert.equal(composeForRole(doc({ tables: [t2] }), t2, "SELECT", "anon").deniedByDefault, false);
  });
});

describe("trigger assignment", () => {
  const t = table({
    name: "docs",
    triggers: [
      trigger({ name: "ins_upd", events: ["INSERT", "UPDATE"], timing: "BEFORE" }),
      trigger({ name: "del_after", events: ["DELETE"], timing: "AFTER" }),
      trigger({ name: "trunc", events: ["TRUNCATE"], timing: "AFTER", level: "STATEMENT" })
    ]
  });
  const d = doc({ tables: [t] });
  const idx = buildReverseFkIndex(d);

  it("puts an INSERT|UPDATE trigger into both cells", () => {
    assert.deepEqual(
      buildCell(d, t, "INSERT", idx).beforeTriggers.map((x) => x.name),
      ["ins_upd"]
    );
    assert.deepEqual(
      buildCell(d, t, "UPDATE", idx).beforeTriggers.map((x) => x.name),
      ["ins_upd"]
    );
    assert.equal(buildCell(d, t, "DELETE", idx).beforeTriggers.length, 0);
    assert.deepEqual(
      buildCell(d, t, "DELETE", idx).afterTriggers.map((x) => x.name),
      ["del_after"]
    );
    assert.equal(buildCell(d, t, "SELECT", idx).beforeTriggers.length, 0);
  });

  it("puts a TRUNCATE-only trigger into no cell", () => {
    for (const op of OPERATIONS) {
      const cell = buildCell(d, t, op, idx);
      const names = [...cell.beforeTriggers, ...cell.afterTriggers, ...cell.insteadTriggers].map((x) => x.name);
      assert.ok(!names.includes("trunc"), op);
    }
  });
});

describe("foreign key propagation", () => {
  it("follows CASCADE transitively and stops at SET NULL / RESTRICT", () => {
    const d = doc({
      tables: [
        table({ name: "org" }),
        table({ name: "team", constraints: [fk("team_org", "org", "CASCADE")] }),
        table({ name: "doc", constraints: [fk("doc_team", "team", "CASCADE")] }),
        table({ name: "log", constraints: [fk("log_team", "team", "SET NULL")] }),
        table({ name: "keep", constraints: [fk("keep_doc", "doc", "RESTRICT")] })
      ]
    });
    const effects = cascadeEffects(buildReverseFkIndex(d), "public", "org", "DELETE");
    assert.equal(effects.length, 1);
    const team = effects[0];
    assert.equal(team?.table, "team");
    assert.equal(team?.resultingOperation, "DELETE");
    const children = team?.children ?? [];
    assert.deepEqual(
      children.map((c) => [c.table, c.resultingOperation]),
      [
        ["doc", "DELETE"],
        ["log", "UPDATE"]
      ]
    );
    assert.deepEqual(
      children[0]?.children.map((c) => [c.table, c.resultingOperation]),
      [["keep", "BLOCK"]]
    );
    assert.equal(countCascadeNodes(effects), 4);
  });

  it("stops at cycles and self references as soon as a table reappears on the path", () => {
    const d = doc({
      tables: [
        table({ name: "a", constraints: [fk("a_b", "b", "CASCADE")] }),
        table({ name: "b", constraints: [fk("b_a", "a", "CASCADE")] }),
        table({ name: "folder", constraints: [fk("folder_parent", "folder", "CASCADE")] })
      ]
    });
    const idx = buildReverseFkIndex(d);
    const fromA = cascadeEffects(idx, "public", "a", "DELETE");
    assert.equal(fromA[0]?.table, "b");
    assert.equal(fromA[0]?.cycle, false);
    assert.equal(fromA[0]?.children[0]?.table, "a");
    assert.equal(fromA[0]?.children[0]?.cycle, true);
    assert.equal(fromA[0]?.children[0]?.children.length, 0);

    const self = cascadeEffects(idx, "public", "folder", "DELETE");
    assert.equal(self.length, 1);
    assert.equal(self[0]?.cycle, true);
  });

  it("shows ON UPDATE in the UPDATE cell, independently of ON DELETE", () => {
    const d = doc({
      tables: [table({ name: "p" }), table({ name: "c", constraints: [fk("c_p", "p", "NO ACTION", "CASCADE")] })]
    });
    const idx = buildReverseFkIndex(d);
    const p = d.tables[0];
    assert.ok(p);
    assert.equal(buildCell(d, p, "UPDATE", idx).cascades[0]?.resultingOperation, "UPDATE");
    assert.equal(buildCell(d, p, "DELETE", idx).cascades[0]?.resultingOperation, "BLOCK");
    assert.equal(buildCell(d, p, "INSERT", idx).cascades.length, 0);
  });

  it("includes foreign keys from other schemas on the referenced side", () => {
    const d = doc({
      tables: [table({ name: "employees" })],
      externalForeignKeys: [{ ...fk("x", "employees", "CASCADE"), from: { schema: "other", table: "sessions" } }]
    });
    const effects = cascadeEffects(buildReverseFkIndex(d), "public", "employees", "DELETE");
    assert.equal(effects[0]?.schema, "other");
    assert.equal(effects[0]?.children.length, 0);
  });
});

describe("GRANT differences from the Supabase default", () => {
  it("reports nothing when every privilege is granted", () => {
    assert.deepEqual(grantDiffs(table({ name: "t" })), []);
  });

  it("does not report a revoked TRUNCATE", () => {
    const grants = defaultGrants().filter((g) => g.privilege !== "TRUNCATE");
    assert.deepEqual(grantDiffs(table({ name: "t", grants })), []);
  });

  it("reports revoked privileges and column-level grants", () => {
    const grants = defaultGrants().filter((g) => !(g.grantee === "anon" && g.privilege === "DELETE"));
    grants.push({ grantee: "authenticated", privilege: "UPDATE", columns: ["name"] });
    const diffs = grantDiffs(table({ name: "t", grants }));
    assert.deepEqual(diffs, [
      { role: "anon", missing: ["DELETE"], columnGrants: [] },
      { role: "authenticated", missing: [], columnGrants: [{ privilege: "UPDATE", columns: ["name"] }] }
    ]);
  });
});

describe("omitted policy expressions (PostgreSQL skips them when combining policies)", () => {
  const only = (p: Parameters<typeof policy>[0]) => {
    const t = table({ name: "t", policies: [policy(p)] });
    return { t, d: doc({ tables: [t] }) };
  };
  const auth = (p: Parameters<typeof policy>[0], op: (typeof OPERATIONS)[number]) => {
    const { t, d } = only(p);
    return composeForRole(d, t, op, "authenticated");
  };

  it("SELECT / DELETE without USING grant no rows", () => {
    for (const op of ["SELECT", "DELETE"] as const) {
      const r = auth({ name: "p", command: op }, op);
      assert.equal(r.permissive[0]?.usingOmitted, true, op);
      assert.equal(r.deniedByDefault, true, op);
    }
  });

  it("INSERT without WITH CHECK allows no rows", () => {
    const r = auth({ name: "p", command: "INSERT" }, "INSERT");
    assert.equal(r.permissive[0]?.withCheckOmitted, true);
    assert.equal(r.deniedByDefault, true);
  });

  it("UPDATE without WITH CHECK reuses USING; UPDATE without USING targets no rows", () => {
    const usingOnly = auth({ name: "p", command: "UPDATE", using: "(v > 0)" }, "UPDATE");
    assert.equal(usingOnly.permissive[0]?.withCheckFromUsing, true);
    assert.equal(usingOnly.permissive[0]?.withCheckOmitted, false);
    assert.equal(usingOnly.deniedByDefault, false);
    const checkOnly = auth({ name: "p", command: "UPDATE", withCheck: "(v < 100)" }, "UPDATE");
    assert.equal(checkOnly.permissive[0]?.usingOmitted, true);
    assert.equal(checkOnly.deniedByDefault, true);
    const neither = auth({ name: "p", command: "UPDATE" }, "UPDATE");
    assert.equal(neither.permissive[0]?.usingOmitted, true);
    assert.equal(neither.permissive[0]?.withCheckOmitted, true);
  });

  it("ALL with only WITH CHECK allows INSERT but grants no rows to SELECT / UPDATE / DELETE", () => {
    const p = { name: "p", command: "ALL" as const, withCheck: "(v < 100)" };
    assert.equal(auth(p, "INSERT").deniedByDefault, false);
    for (const op of ["SELECT", "UPDATE", "DELETE"] as const) assert.equal(auth(p, op).deniedByDefault, true, op);
  });

  it("ALL with only USING checks inserted rows with USING", () => {
    const r = auth({ name: "p", command: "ALL", using: "(v > 0)" }, "INSERT");
    assert.equal(r.permissive[0]?.withCheck, "(v > 0)");
    assert.equal(r.permissive[0]?.withCheckOmitted, false);
    assert.equal(r.deniedByDefault, false);
  });

  it("an omitted PERMISSIVE policy does not deny when another PERMISSIVE policy supplies the expression", () => {
    const t = table({
      name: "t",
      policies: [policy({ name: "a", command: "SELECT" }), policy({ name: "b", command: "SELECT", using: "(v > 0)" })]
    });
    assert.equal(composeForRole(doc({ tables: [t] }), t, "SELECT", "authenticated").deniedByDefault, false);
  });

  it("an omitted RESTRICTIVE policy is marked as omitted and never causes a denial", () => {
    const t = table({
      name: "t",
      policies: [
        policy({ name: "perm", command: "SELECT", using: "true" }),
        policy({ name: "restr", command: "SELECT", permissive: false })
      ]
    });
    const r = composeForRole(doc({ tables: [t] }), t, "SELECT", "authenticated");
    assert.equal(r.restrictive[0]?.usingOmitted, true);
    assert.equal(r.deniedByDefault, false);
  });
});
