/**
 * Pure functions that build the "table × operation" cells from the facts in rules.json.
 * Follows PostgreSQL's RLS semantics: per role, PERMISSIVE policies are ORed and RESTRICTIVE ones ANDed.
 */
import type { FkAction, ForeignKeyConstraint, Operation, Policy, RulesDocument, TableRules, Trigger } from "./types.ts";

export interface CellPolicy {
  policy: Policy;
  fromAll: boolean;
  /** Expressions evaluated in this cell (UPDATE uses both using and withCheck). */
  using: string | null;
  withCheck: string | null;
  /** There is no WITH CHECK, so USING is also used to check new rows. */
  withCheckFromUsing: boolean;
  /**
   * The operation needs USING but the policy has none. PostgreSQL skips an omitted expression when it combines
   * policies, so a PERMISSIVE policy then grants no rows and a RESTRICTIVE one restricts nothing (it is not `true`).
   */
  usingOmitted: boolean;
  /** Same for WITH CHECK, after the UPDATE / ALL fallback to USING. */
  withCheckOmitted: boolean;
}

export interface RoleComposition {
  role: string;
  bypassRls: boolean;
  permissive: CellPolicy[];
  restrictive: CellPolicy[];
  /** No PERMISSIVE policy supplies an expression for a side the operation needs, so RLS denies every row. */
  deniedByDefault: boolean;
  /** Storage cells only: RESTRICTIVE policies whose bucket condition is always false in this bucket, denying every row. */
  deniedByRestrictive?: string[];
  hasGrant: boolean;
}

export interface CascadeEffect {
  table: string;
  schema: string;
  constraint: string;
  columns: string[];
  action: FkAction;
  /** What happens to the child rows. Anything other than DELETE CASCADE results in an UPDATE (or a rejection). */
  resultingOperation: "DELETE" | "UPDATE" | "BLOCK";
  cycle: boolean;
  children: CascadeEffect[];
}

export interface Cell {
  table: string;
  operation: Operation;
  policies: CellPolicy[];
  roles: RoleComposition[];
  beforeTriggers: Trigger[];
  afterTriggers: Trigger[];
  insteadTriggers: Trigger[];
  cascades: CascadeEffect[];
}

/** Returns the policies that apply to the operation, expanding cmd=ALL. */
export function policiesForOperation(table: TableRules, op: Operation): CellPolicy[] {
  const out: CellPolicy[] = [];
  for (const policy of table.policies) {
    if (policy.command !== op && policy.command !== "ALL") continue;
    const fromAll = policy.command === "ALL";
    let using: string | null = null;
    let withCheck: string | null = null;
    let withCheckFromUsing = false;
    switch (op) {
      case "SELECT":
      case "DELETE":
        using = policy.using;
        break;
      case "INSERT":
        // For an ALL policy without WITH CHECK, PostgreSQL checks inserted rows with USING
        withCheck = policy.withCheck ?? policy.using;
        withCheckFromUsing = policy.withCheck === null && policy.using !== null;
        break;
      case "UPDATE":
        using = policy.using;
        withCheck = policy.withCheck ?? policy.using;
        withCheckFromUsing = policy.withCheck === null && policy.using !== null;
        break;
    }
    out.push({
      policy,
      fromAll,
      using,
      withCheck,
      withCheckFromUsing,
      usingOmitted: needsUsing(op) && using === null,
      withCheckOmitted: needsWithCheck(op) && withCheck === null
    });
  }
  return out;
}

const needsUsing = (op: Operation) => op !== "INSERT";
const needsWithCheck = (op: Operation) => op === "INSERT" || op === "UPDATE";

export function hasPrivilege(table: Pick<TableRules, "grants">, role: string, op: Operation): boolean {
  // A column-level grant still permits the operation on those columns, so it counts as a grant
  return table.grants.some((g) => (g.grantee === role || g.grantee === "PUBLIC") && g.privilege === op);
}

/** Roles to display: anon / authenticated / service_role plus any role named in the table's policies. */
export function displayRoles(doc: RulesDocument, table: TableRules): string[] {
  const set = new Set<string>(["anon", "authenticated"]);
  for (const p of table.policies) for (const r of p.roles) if (r !== "public") set.add(r);
  const ordered = [...set].sort((a, b) => roleOrder(a) - roleOrder(b) || a.localeCompare(b));
  if (doc.roles.some((r) => r.name === "service_role")) ordered.push("service_role");
  return ordered;
}

function roleOrder(role: string): number {
  if (role === "anon") return 0;
  if (role === "authenticated") return 1;
  return 2;
}

export function composeForRole(doc: RulesDocument, table: TableRules, op: Operation, role: string): RoleComposition {
  const info = doc.roles.find((r) => r.name === role);
  const bypassRls = Boolean(info?.bypassRls || info?.superuser);
  const applicable = policiesForOperation(table, op).filter(
    (cp) => cp.policy.roles.includes(role) || cp.policy.roles.includes("public")
  );
  const permissive = applicable.filter((cp) => cp.policy.permissive);
  const restrictive = applicable.filter((cp) => !cp.policy.permissive);
  return {
    role,
    bypassRls,
    permissive,
    restrictive,
    deniedByDefault:
      table.rls.enabled &&
      !bypassRls &&
      ((needsUsing(op) && !permissive.some((cp) => !cp.usingOmitted)) ||
        (needsWithCheck(op) && !permissive.some((cp) => !cp.withCheckOmitted))),
    hasGrant: hasPrivilege(table, role, op)
  };
}

function triggersForEvent(table: TableRules, event: Exclude<Operation, "SELECT">): Trigger[] {
  return table.triggers.filter((t) => t.events.includes(event));
}

type FkIndex = Map<string, { schema: string; table: string; fk: ForeignKeyConstraint }[]>;

/** Referenced table name → foreign keys that reference it. */
export function buildReverseFkIndex(doc: RulesDocument): FkIndex {
  const index: FkIndex = new Map();
  const add = (schema: string, table: string, fk: ForeignKeyConstraint) => {
    if (fk.references.schema !== doc.source.schema) return;
    const list = index.get(fk.references.table) ?? [];
    list.push({ schema, table, fk });
    index.set(fk.references.table, list);
  };
  for (const t of doc.tables) {
    for (const c of t.constraints) if (c.kind === "foreign") add(doc.source.schema, t.name, c);
  }
  for (const ext of doc.externalForeignKeys) {
    const { from, ...rest } = ext;
    add(from.schema, from.table, { ...rest, kind: "foreign" });
  }
  return index;
}

/**
 * Returns, as a tree, how a DELETE / UPDATE propagates to referencing tables through foreign keys.
 * Only CASCADE recurses into the child's own references. SET NULL / SET DEFAULT update the child and
 * RESTRICT / NO ACTION reject the statement while referencing rows exist, so the chain stops there.
 */
export function cascadeEffects(
  index: FkIndex,
  schema: string,
  table: string,
  op: "DELETE" | "UPDATE",
  path: ReadonlySet<string> = new Set([`${schema}.${table}`])
): CascadeEffect[] {
  const effects: CascadeEffect[] = [];
  for (const ref of index.get(table) ?? []) {
    const action = op === "DELETE" ? ref.fk.onDelete : ref.fk.onUpdate;
    const resultingOperation: CascadeEffect["resultingOperation"] =
      action === "CASCADE" ? op : action === "SET NULL" || action === "SET DEFAULT" ? "UPDATE" : "BLOCK";
    const key = `${ref.schema}.${ref.table}`;
    const cycle = path.has(key);
    let children: CascadeEffect[] = [];
    // Stop at self references and cycles as soon as a table reappears on the current path
    if (!cycle && action === "CASCADE" && ref.schema === schema) {
      children = cascadeEffects(index, schema, ref.table, op, new Set([...path, key]));
    }
    effects.push({
      table: ref.table,
      schema: ref.schema,
      constraint: ref.fk.name,
      columns: ref.fk.columns,
      action,
      resultingOperation,
      cycle,
      children
    });
  }
  return effects.sort((a, b) => actionRank(a.action) - actionRank(b.action) || a.table.localeCompare(b.table));
}

function actionRank(a: FkAction): number {
  return a === "CASCADE" ? 0 : a === "SET NULL" || a === "SET DEFAULT" ? 1 : 2;
}

export function countCascadeNodes(effects: CascadeEffect[]): number {
  return effects.reduce((n, e) => n + 1 + countCascadeNodes(e.children), 0);
}

export function buildCell(doc: RulesDocument, table: TableRules, op: Operation, fkIndex: FkIndex): Cell {
  const triggers = op === "SELECT" ? [] : triggersForEvent(table, op);
  return {
    table: table.name,
    operation: op,
    policies: policiesForOperation(table, op),
    roles: displayRoles(doc, table).map((role) => composeForRole(doc, table, op, role)),
    beforeTriggers: triggers.filter((t) => t.timing === "BEFORE"),
    afterTriggers: triggers.filter((t) => t.timing === "AFTER"),
    insteadTriggers: triggers.filter((t) => t.timing === "INSTEAD OF"),
    cascades: op === "DELETE" || op === "UPDATE" ? cascadeEffects(fkIndex, doc.source.schema, table.name, op) : []
  };
}

/**
 * Privileges compared against the Supabase default, which grants every table privilege to anon / authenticated /
 * service_role. TRUNCATE is left out: it stays granted on nearly every table, so a difference in it carries no
 * information.
 */
export const SUPABASE_DEFAULT_PRIVILEGES = ["SELECT", "INSERT", "UPDATE", "DELETE", "REFERENCES", "TRIGGER"];
export const SUPABASE_DEFAULT_GRANTEES = ["anon", "authenticated", "service_role"];

export interface GrantDiff {
  role: string;
  missing: string[];
  columnGrants: { privilege: string; columns: string[] }[];
}

/** Differences from the Supabase default in SUPABASE_DEFAULT_PRIVILEGES. Roles without a difference are omitted. */
export function grantDiffs(table: Pick<TableRules, "grants">): GrantDiff[] {
  const out: GrantDiff[] = [];
  for (const role of SUPABASE_DEFAULT_GRANTEES) {
    const tableLevel = new Set(
      table.grants
        .filter((g) => (g.grantee === role || g.grantee === "PUBLIC") && g.columns === null)
        .map((g) => g.privilege)
    );
    const missing = SUPABASE_DEFAULT_PRIVILEGES.filter((p) => !tableLevel.has(p));
    const columnGrants = table.grants
      .filter((g) => g.grantee === role && g.columns !== null)
      .map((g) => ({ privilege: g.privilege, columns: g.columns ?? [] }));
    if (missing.length > 0 || columnGrants.length > 0) out.push({ role, missing, columnGrants });
  }
  return out;
}
