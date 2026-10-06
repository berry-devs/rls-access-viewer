/**
 * Assigns storage.objects policies to buckets by reading the bucket_id conditions of their expressions,
 * then builds bucket × operation cells with the same composition rules as table cells.
 */
import { parseCondition, type ConditionNode } from "../render/sql.ts";
import { buildCell, composeForRole, displayRoles, policiesForOperation, type Cell } from "./cells.ts";
import type { BucketInfo, Operation, Policy, RulesDocument, TableRules } from "./types.ts";

/**
 * Which buckets an expression can match.
 * - buckets: the expression requires bucket_id to be one of `ids`
 * - all: no bucket condition, so the expression applies to every bucket
 * - unrecognized: bucket_id is mentioned in a form that is not read (e.g. `<>`, a function); treated as every bucket
 */
export type BucketScope = { kind: "buckets"; ids: string[] } | { kind: "all" } | { kind: "unrecognized" };

const ALL: BucketScope = { kind: "all" };
const UNRECOGNIZED: BucketScope = { kind: "unrecognized" };

const COLUMN = String.raw`(?:(?:"?[A-Za-z_][\w$]*"?\.){0,2}"?bucket_id"?)`;
const LITERAL = String.raw`'(?:[^']|'')*'`;
const CAST = String.raw`(?:\s*::\s*(?:text|character varying|varchar|name))?`;
const EQ_LEFT = new RegExp(String.raw`^${COLUMN}\s*=\s*(${LITERAL})${CAST}$`, "i");
const EQ_RIGHT = new RegExp(String.raw`^(${LITERAL})${CAST}\s*=\s*${COLUMN}$`, "i");
// pg_get_expr prints `bucket_id IN ('a', 'b')` as `bucket_id = ANY (ARRAY['a'::text, 'b'::text])`
const ANY_ARRAY = new RegExp(
  String.raw`^${COLUMN}\s*=\s*ANY\s*\(\s*\(?\s*ARRAY\s*\[(.*)\]\s*\)?${CAST}(?:\[\])?\s*\)$`,
  "is"
);
const IN_LIST = new RegExp(String.raw`^${COLUMN}\s+IN\s*\((.*)\)$`, "is");
const MENTIONS = /\bbucket_id\b/i;

const unquote = (literal: string) => literal.slice(1, -1).replace(/''/g, "'");

/** Splits `'a'::text, 'b'::text` into literal values; null if anything else appears in the list. */
function literalList(list: string): string[] | null {
  const re = new RegExp(String.raw`\s*(${LITERAL})${CAST}\s*(?:,|$)`, "y");
  const out: string[] = [];
  let m: RegExpExecArray | null;
  let last = 0;
  while (last < list.length && (m = re.exec(list)) !== null) {
    out.push(unquote(m[1] as string));
    last = re.lastIndex;
  }
  return last === list.length && out.length ? out : null;
}

/** Strips redundant outer parentheses of a leaf (the condition splitter keeps them on some leaves). */
function stripParens(sql: string): string {
  let s = sql.trim();
  while (s.startsWith("(") && s.endsWith(")")) {
    let depth = 0;
    let wraps = true;
    for (let i = 0; i < s.length; i++) {
      if (s[i] === "(") depth++;
      else if (s[i] === ")") depth--;
      if (depth === 0 && i < s.length - 1) {
        wraps = false;
        break;
      }
    }
    if (!wraps) break;
    s = s.slice(1, -1).trim();
  }
  return s;
}

function leafScope(sql: string): BucketScope {
  const s = stripParens(sql);
  const eq = EQ_LEFT.exec(s) ?? EQ_RIGHT.exec(s);
  if (eq) return { kind: "buckets", ids: [unquote(eq[1] as string)] };
  const list = ANY_ARRAY.exec(s) ?? IN_LIST.exec(s);
  if (list) {
    const ids = literalList(list[1] as string);
    if (ids) return { kind: "buckets", ids: [...new Set(ids)] };
  }
  return MENTIONS.test(s) ? UNRECOGNIZED : ALL;
}

function nodeScope(node: ConditionNode): BucketScope {
  if (node.kind === "raw") return MENTIONS.test(node.sql) ? UNRECOGNIZED : ALL;
  if (node.kind === "leaf") return leafScope(node.sql);
  const scopes = node.children.map(nodeScope);
  if (node.kind === "and") {
    // A row must pass every conjunct, so known bucket sets intersect; other conjuncts do not widen them
    const sets = scopes.filter((s): s is Extract<BucketScope, { kind: "buckets" }> => s.kind === "buckets");
    if (sets.length) {
      const [first, ...rest] = sets as [
        Extract<BucketScope, { kind: "buckets" }>,
        ...Extract<BucketScope, { kind: "buckets" }>[]
      ];
      return { kind: "buckets", ids: first.ids.filter((id) => rest.every((r) => r.ids.includes(id))) };
    }
    return scopes.some((s) => s.kind === "unrecognized") ? UNRECOGNIZED : ALL;
  }
  // OR: one disjunct without a bucket condition opens the expression to every bucket
  if (scopes.every((s) => s.kind === "buckets")) {
    return { kind: "buckets", ids: [...new Set(scopes.flatMap((s) => (s.kind === "buckets" ? s.ids : [])))] };
  }
  return scopes.some((s) => s.kind === "unrecognized") ? UNRECOGNIZED : ALL;
}

/** Bucket scope of one policy expression. Never throws: an expression it cannot split is read as a whole. */
export function bucketScope(sql: string): BucketScope {
  try {
    return nodeScope(parseCondition(sql));
  } catch {
    return MENTIONS.test(sql) ? UNRECOGNIZED : ALL;
  }
}

const covers = (scope: BucketScope, bucket: string) => scope.kind !== "buckets" || scope.ids.includes(bucket);

/** How a policy relates to the buckets, for the expressions one operation evaluates. */
export interface PolicyBucketScope {
  policy: Policy;
  /**
   * Buckets whose cells show the policy: the union over the evaluated expressions. For UPDATE, USING selects the
   * target rows and WITH CHECK the new rows, so a policy that moves objects from one bucket to another belongs to both.
   */
  scope: BucketScope;
}

/** Scope of each policy that applies to the operation (cmd=ALL expanded), as evaluated by that operation. */
export function policyScopes(objects: TableRules, op: Operation): PolicyBucketScope[] {
  return policiesForOperation(objects, op).map((cp) => {
    const scopes = [cp.using, cp.withCheck].filter((e): e is string => e !== null).map(bucketScope);
    let scope: BucketScope;
    if (scopes.some((s) => s.kind === "unrecognized")) scope = UNRECOGNIZED;
    else if (!scopes.length || scopes.some((s) => s.kind === "all")) scope = ALL;
    else scope = { kind: "buckets", ids: [...new Set(scopes.flatMap((s) => (s.kind === "buckets" ? s.ids : [])))] };
    return { policy: cp.policy, scope };
  });
}

export interface BucketCell extends Cell {
  bucket: string;
  /**
   * Policies in this cell that are not limited to it: no bucket condition (all), a bucket condition that is not read
   * (unrecognized), or a RESTRICTIVE policy scoped to other buckets, which is always false here (outOfBucket).
   */
  sharedPolicies: { name: string; reason: "all" | "unrecognized" | "outOfBucket" }[];
}

/**
 * The cell of one bucket and operation: storage.objects restricted to the policies whose evaluated expressions can
 * match the bucket, composed exactly like a table cell (PERMISSIVE = OR, RESTRICTIVE = AND, default deny, BYPASSRLS).
 */
export function buildBucketCell(doc: RulesDocument, objects: TableRules, bucket: string, op: Operation): BucketCell {
  // A PERMISSIVE policy scoped to other buckets grants nothing here and is left out. A RESTRICTIVE one is kept: its
  // bucket condition is false for every object of this bucket, so it denies the operation, and dropping it would
  // show the bucket as more open than it is
  const scoped = policyScopes(objects, op).filter((p) => !p.policy.permissive || covers(p.scope, bucket));
  const outOfBucket = new Set(scoped.filter((p) => !covers(p.scope, bucket)).map((p) => p.policy.name));
  const names = new Set(scoped.map((p) => p.policy));
  // Only this operation's policies are kept; buildCell expands cmd=ALL again from this subset
  const restricted: TableRules = { ...objects, policies: objects.policies.filter((p) => names.has(p)) };
  const cell = buildCell(doc, restricted, op, new Map());
  // Roles come from every policy of storage.objects, so a role named only by another bucket's policy is still shown
  // here (as denied by default); only the composition uses this bucket's subset
  const roles = displayRoles(doc, objects)
    .map((role) => composeForRole(doc, restricted, op, role))
    .map((r) => {
      if (r.bypassRls || !objects.rls.enabled) return r;
      const denying = r.restrictive.filter((cp) => outOfBucket.has(cp.policy.name)).map((cp) => cp.policy.name);
      return denying.length ? { ...r, deniedByDefault: true, deniedByRestrictive: denying } : r;
    });
  return {
    ...cell,
    roles,
    bucket,
    sharedPolicies: scoped
      .filter((p) => p.scope.kind !== "buckets" || outOfBucket.has(p.policy.name))
      .map((p) => ({
        name: p.policy.name,
        reason: outOfBucket.has(p.policy.name)
          ? "outOfBucket"
          : p.scope.kind === "unrecognized"
            ? "unrecognized"
            : "all"
      }))
  };
}

/** Bucket ids named by the bucket conditions of any policy, sorted. */
export function bucketIdsInPolicies(objects: TableRules): string[] {
  const ids = new Set<string>();
  for (const policy of objects.policies) {
    for (const expr of [policy.using, policy.withCheck]) {
      if (expr === null) continue;
      const scope = bucketScope(expr);
      if (scope.kind === "buckets") for (const id of scope.ids) ids.add(id);
    }
  }
  return [...ids].sort();
}

/** Bucket ids named by policies that do not exist in storage.buckets (typos or dropped buckets). */
export function unknownBucketReferences(
  objects: TableRules,
  buckets: BucketInfo[]
): { policy: string; bucket: string }[] {
  const known = new Set(buckets.map((b) => b.id));
  const out: { policy: string; bucket: string }[] = [];
  const seen = new Set<string>();
  for (const policy of objects.policies) {
    for (const expr of [policy.using, policy.withCheck]) {
      if (expr === null) continue;
      const scope = bucketScope(expr);
      if (scope.kind !== "buckets") continue;
      for (const id of scope.ids) {
        const key = `${policy.name}\u0000${id}`;
        if (!known.has(id) && !seen.has(key)) {
          seen.add(key);
          out.push({ policy: policy.name, bucket: id });
        }
      }
    }
  }
  return out;
}
