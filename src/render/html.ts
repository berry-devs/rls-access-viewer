import { createHash } from "node:crypto";
import {
  buildCell,
  buildReverseFkIndex,
  composeForRole,
  countCascadeNodes,
  grantDiffs,
  SUPABASE_DEFAULT_PRIVILEGES,
  type CascadeEffect,
  type Cell,
  type CellPolicy,
  type RoleComposition
} from "../model/cells.ts";
import { matchTags, type CompiledTag } from "../model/config.ts";
import { analyzeFunction, functionsCalledInExpression } from "../model/plpgsql.ts";
import { redactDeep } from "../model/redact.ts";
import { bucketIdsInPolicies, buildBucketCell, unknownBucketReferences, type BucketCell } from "../model/storage.ts";
import {
  OPERATIONS,
  type BucketInfo,
  type FunctionAnalysis,
  type FunctionInfo,
  type Operation,
  type RulesDocument,
  type TableRules,
  type Trigger
} from "../model/types.ts";
import { SCRIPT, STYLE } from "./assets.ts";
import {
  renderFunctionRules,
  renderPolicyFunctions,
  type FunctionRulesCtx,
  type PolicyFunctionRef
} from "./functionRules.ts";
import { escapeHtml as esc, highlightSql, leaves, parseCondition, type ConditionNode } from "./sql.ts";

export interface RenderOptions {
  tags: CompiledTag[];
}

/** Encodes a name into a valid, collision-free HTML id (every non-alphanumeric character becomes hex). */
export function anchorId(prefix: string, ...parts: string[]): string {
  const enc = (s: string) => s.replace(/[^A-Za-z0-9_-]/g, (c) => `.${c.codePointAt(0)?.toString(16)}`);
  return [prefix, ...parts.map(enc)].join("--");
}

/**
 * JSON for embedding inside <script>. `<`, `>` and `&` are escaped so that `</script>` or `<!--`
 * inside a definition cannot break out of the script context.
 */
export function jsonForScript(value: unknown): string {
  return JSON.stringify(value)
    .replace(/</g, "\\u003c")
    .replace(/>/g, "\\u003e")
    .replace(/&/g, "\\u0026")
    .replace(/\u2028/g, "\\u2028")
    .replace(/\u2029/g, "\\u2029");
}

/** rules.json is untrusted input: a count that is not a finite number is shown as "?" rather than interpolated. */
const count = (v: unknown): string => (Number.isFinite(Number(v)) ? String(Number(v)) : "?");

const sha256Base64 = (s: string) => createHash("sha256").update(s, "utf8").digest("base64");

interface Ctx {
  doc: RulesDocument;
  tags: CompiledTag[];
  linkFunction: (name: string) => string | null;
  rules: FunctionRulesCtx;
  /** Target-schema functions called from a policy expression. */
  policyCalls: (sql: string) => string[];
}

/** Renders rules.json as a single self-contained HTML viewer (no external resources). */
export function renderHtml(input: RulesDocument, options: RenderOptions): string {
  // rules.json may have been edited by hand, so redact again before rendering
  const doc = redactDeep(input);
  const fnAnchors = new Map<string, string>();
  for (const [i, f] of doc.functions.entries()) {
    if (!fnAnchors.has(f.name)) fnAnchors.set(f.name, anchorId("fn", f.name, String(i)));
  }
  const schemaPrefix = `${doc.source.schema}.`;
  const linkFunction = (name: string) => {
    const bare = name.startsWith(schemaPrefix) ? name.slice(schemaPrefix.length) : name;
    if (bare.includes(".")) return null;
    const id = fnAnchors.get(bare);
    return id ? `#${id}` : null;
  };
  // Trigger functions take no arguments, so a zero-argument overload is preferred when names collide
  const fnByName = new Map<string, FunctionInfo>();
  for (const f of doc.functions) {
    const current = fnByName.get(f.name);
    if (!current || (current.identityArguments !== "" && f.identityArguments === "")) fnByName.set(f.name, f);
  }
  const knownFunctions = new Set(doc.functions.map((f) => f.name));
  const overloads = new Map<string, number>();
  for (const f of doc.functions) overloads.set(f.name, (overloads.get(f.name) ?? 0) + 1);
  const analyses = new Map<FunctionInfo, FunctionAnalysis>();
  // rules.json from older versions has no analysis; compute it here (analyzeFunction never throws)
  const analysisOf = (name: string) => {
    const f = fnByName.get(name);
    if (!f) return undefined;
    let a = analyses.get(f);
    if (!a) {
      a = f.analysis ?? analyzeFunction(f, doc.source.schema, knownFunctions);
      analyses.set(f, a);
    }
    return a;
  };
  const tableNames = new Set(doc.tables.map((t) => t.name));
  // The same expression appears in up to four cells (FOR ALL policies), so the calls are read once per text
  const callsByExpression = new Map<string, string[]>();
  const policyCalls = (sql: string) => {
    let calls = callsByExpression.get(sql);
    if (!calls) {
      calls = functionsCalledInExpression(sql, doc.source.schema, knownFunctions);
      callsByExpression.set(sql, calls);
    }
    return calls;
  };
  const ctx: Ctx = {
    doc,
    tags: options.tags,
    linkFunction,
    policyCalls,
    rules: {
      doc,
      linkFunction,
      expression: (sql) => renderExpression({ tags: options.tags, linkFunction }, sql),
      functionOf: (name) => fnByName.get(name),
      isOverloaded: (name) => (overloads.get(name) ?? 0) > 1,
      analysisOf,
      tableHref: (schema, name) =>
        (schema === null || schema === doc.source.schema) && tableNames.has(name) ? `#${anchorId("t", name)}` : null
    }
  };
  const fkIndex = buildReverseFkIndex(doc);
  const cellsByTable = new Map<string, Cell[]>(
    doc.tables.map((t) => [t.name, OPERATIONS.map((op) => buildCell(doc, t, op, fkIndex))])
  );

  const body = [
    renderHeader(doc),
    `<nav class="tabs" aria-label="Sections">
      <a href="#tab-matrix" data-tab="tab-matrix">Tables × operations</a>
      <a href="#tab-functions" data-tab="tab-functions">Functions (RPC)</a>
      <a href="#tab-views" data-tab="tab-views">Views</a>
      <a href="#tab-storage" data-tab="tab-storage">Storage</a>
      <a href="#tab-meta" data-tab="tab-meta">Excluded &amp; reference</a>
    </nav>`,
    `<section id="tab-matrix" class="tab">${renderMatrix(ctx, cellsByTable)}${doc.tables
      .map((t) => renderTable(ctx, t, cellsByTable.get(t.name) ?? []))
      .join("")}</section>`,
    `<section id="tab-functions" class="tab">${renderFunctions(ctx)}</section>`,
    `<section id="tab-views" class="tab">${renderViews(ctx)}</section>`,
    `<section id="tab-storage" class="tab">${renderStorage(ctx)}</section>`,
    `<section id="tab-meta" class="tab">${renderMeta(doc)}</section>`,
    `<script type="application/json" id="rules-json">${jsonForScript(doc)}</script>`
  ].join("\n");

  // Built only from fixed strings and base64 hashes, so it contains nothing that needs attribute escaping
  const csp = [
    "default-src 'none'",
    `style-src 'sha256-${sha256Base64(STYLE)}'`,
    `script-src 'sha256-${sha256Base64(SCRIPT)}'`,
    "img-src 'none'",
    "base-uri 'none'",
    "form-action 'none'"
  ].join("; ");

  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="${csp}">
<meta name="referrer" content="no-referrer">
<title>RLS Access Viewer (${esc(doc.source.schema)})</title>
<style>${STYLE}</style>
</head>
<body>
${body}
<script>${SCRIPT}</script>
</body>
</html>
`;
}

function renderHeader(doc: RulesDocument): string {
  const policies = doc.tables.reduce((n, t) => n + t.policies.length, 0);
  const rlsOff = doc.tables.filter((t) => !t.rls.enabled);
  const secdef = doc.functions.filter((f) => f.securityDefiner);
  const secdefWarn = secdef.filter(isSecdefWarning);
  const viewWarn = doc.views.filter((v) => v.kind === "materialized" || !v.securityInvoker);
  const warn = (n: number, label: string, href: string) =>
    `<li class="${n > 0 ? "warn" : "ok"}"><a href="${href}">${esc(label)}: ${n}</a></li>`;
  return `<header>
  <h1>RLS Access Viewer <small>schema: ${esc(doc.source.schema)}</small></h1>
  <p class="meta">Generated: ${esc(doc.generatedAt)} / PostgreSQL ${esc(doc.source.serverVersion)} /
  ${doc.tables.length} tables / ${doc.views.length} views / ${policies} policies / ${doc.functions.length} functions (${secdef.length} SECURITY DEFINER)</p>
  <ul class="warnings">
    ${warn(rlsOff.length, "Tables with RLS disabled", "#tab-matrix")}
    ${warn(secdefWarn.length, "SECURITY DEFINER functions to review", "#tab-functions")}
    ${warn(viewWarn.length, "Views that may bypass RLS", "#tab-views")}
    ${doc.storage ? warn(doc.storage.buckets.filter((b) => b.public).length, "Public storage buckets", "#tab-storage") : ""}
  </ul>
</header>`;
}

/* ---------- Matrix ---------- */

function renderMatrix(ctx: Ctx, cellsByTable: Map<string, Cell[]>): string {
  const head = `<tr><th>Table</th><th>RLS</th>${OPERATIONS.map((op) => `<th>${op}</th>`).join("")}</tr>`;
  const rows = ctx.doc.tables
    .map((t) => {
      const cells = cellsByTable.get(t.name) ?? [];
      const rls = t.rls.enabled
        ? `<span class="badge ok">on</span>${t.rls.forced ? ' <span class="badge">FORCE</span>' : ""}`
        : `<span class="badge danger">off</span>`;
      return `<tr data-name="${esc(t.name)}" class="${t.rls.enabled ? "" : "row-danger"}">
  <th><a href="#${anchorId("t", t.name)}">${esc(t.name)}</a></th><td>${rls}</td>
  ${cells.map((c) => `<td>${renderMatrixCell(ctx, t, c)}</td>`).join("")}</tr>`;
    })
    .join("\n");
  return `<h2>Tables × operations</h2>
<p class="legend">Legend: number of PERMISSIVE (P) / RESTRICTIVE (R) policies that apply to <b>authenticated</b>;
<span class="badge danger">deny</span> = no PERMISSIVE policy, denied by default; B/A = BEFORE/AFTER triggers; ↯ = tables reached through FK actions.
Click a cell to jump to its details.</p>
<p><input type="search" id="filter" placeholder="Filter by table name" aria-label="Filter by table name"></p>
<div class="scroll"><table class="matrix"><thead>${head}</thead><tbody>${rows}</tbody></table></div>`;
}

function renderMatrixCell(
  ctx: Ctx,
  table: TableRules,
  cell: Cell,
  href = `#${anchorId("c", table.name, cell.operation)}`
): string {
  const parts: string[] = [];
  if (!table.rls.enabled) parts.push('<span class="badge danger">RLS off</span>');
  else {
    // The cell's own compositions are used so that a Storage cell (a subset of the policies) is summarized correctly
    const auth =
      cell.roles.find((r) => r.role === "authenticated") ??
      composeForRole(ctx.doc, table, cell.operation, "authenticated");
    if (!auth.hasGrant) parts.push('<span class="badge">no grant</span>');
    else if (auth.deniedByDefault) parts.push('<span class="badge danger">deny</span>');
    else parts.push(`<span class="badge ok">P${auth.permissive.length}</span>`);
    if (auth.restrictive.length) parts.push(`<span class="badge">R${auth.restrictive.length}</span>`);
    const anon = cell.roles.find((r) => r.role === "anon") ?? composeForRole(ctx.doc, table, cell.operation, "anon");
    if (anon.hasGrant && !anon.deniedByDefault) parts.push('<span class="badge warn">anon</span>');
  }
  if (cell.policies.some((p) => p.fromAll)) parts.push('<span class="badge">ALL</span>');
  if (cell.beforeTriggers.length) parts.push(`<span class="badge">B${cell.beforeTriggers.length}</span>`);
  if (cell.afterTriggers.length) parts.push(`<span class="badge">A${cell.afterTriggers.length}</span>`);
  const cascade = countCascadeNodes(cell.cascades);
  if (cascade) parts.push(`<span class="badge">↯${cascade}</span>`);
  return `<a class="cell" href="${esc(href)}">${parts.join(" ")}</a>`;
}

/* ---------- Table details ---------- */

function renderTable(ctx: Ctx, t: TableRules, cells: Cell[]): string {
  const rls = t.rls.enabled
    ? `RLS: <span class="badge ok">enabled</span>${t.rls.forced ? ' <span class="badge">FORCE RLS (applies to the owner too)</span>' : ""}`
    : `RLS: <span class="badge danger">disabled</span> <span class="danger-text">A role holding the GRANT for an operation can perform it on every row; no row-level restriction applies.</span>`;
  const diffs = grantDiffs(t);
  const grants = diffs.length
    ? `<ul>${diffs
        .map(
          (d) =>
            `<li><b>${esc(d.role)}</b>: ${
              d.missing.length
                ? `<span class="badge warn">revoked from default</span> ${d.missing.map(esc).join(", ")}`
                : ""
            }${d.columnGrants
              .map(
                (c) =>
                  ` <span class="badge warn">column-level</span> ${esc(c.privilege)}(${c.columns.map(esc).join(", ")})`
              )
              .join("")}</li>`
        )
        .join("")}</ul>`
    : `<p class="muted">Same as the Supabase default (${SUPABASE_DEFAULT_PRIVILEGES.join(
        " / "
      )} granted to anon / authenticated / service_role).</p>`;
  const notNull = t.columns.filter((c) => c.notNull);
  return `<article class="table-detail" id="${anchorId("t", t.name)}" data-name="${esc(t.name)}">
<h2>${esc(t.name)}${t.kind === "partitioned" ? ' <span class="badge">partitioned</span>' : ""}${
    t.isPartition ? ' <span class="badge">partition</span>' : ""
  }</h2>
<p>${rls}</p>
<details><summary>GRANTs (difference from the Supabase default)</summary>
<p class="note">TRUNCATE is not compared: Supabase leaves it granted on nearly every table, so a difference in it carries no information.</p>${grants}</details>
<details><summary>Columns (${t.columns.length}) and constraints (${t.constraints.length})</summary>
<table class="plain"><thead><tr><th>Column</th><th>Type</th><th>NOT NULL</th><th>Default</th></tr></thead><tbody>${t.columns
    .map(
      (c) =>
        `<tr><td>${esc(c.name)}</td><td>${esc(c.type)}</td><td>${c.notNull ? "✓" : ""}</td><td>${
          c.default
            ? `<code>${highlightSql(c.default, ctx.linkFunction)}</code>`
            : c.identity
              ? `IDENTITY ${esc(String(c.identity))}`
              : ""
        }</td></tr>`
    )
    .join("")}</tbody></table>
${renderConstraintList(ctx, t)}
<p class="muted">NOT NULL: ${notNull.length ? notNull.map((c) => esc(c.name)).join(", ") : "none"}</p></details>
${cells.map((c) => renderCell(ctx, t, c)).join("")}
</article>`;
}

function renderConstraintList(ctx: Ctx, t: TableRules): string {
  if (!t.constraints.length) return "";
  return `<ul class="constraints">${t.constraints
    .map(
      (c) =>
        `<li><span class="badge">${constraintLabel(c.kind)}</span> ${esc(c.name)}: <code>${highlightSql(
          c.definition,
          ctx.linkFunction
        )}</code></li>`
    )
    .join("")}</ul>`;
}

function constraintLabel(kind: TableRules["constraints"][number]["kind"]): string {
  const labels: Record<string, string> = {
    primary: "PK",
    unique: "UNIQUE",
    exclusion: "EXCLUDE",
    check: "CHECK",
    foreign: "FK"
  };
  return esc(labels[kind] ?? String(kind));
}

interface CellOptions {
  id: string;
  /** Plain text; escaped here. */
  title: string;
  /** HTML shown under the title (already escaped). */
  prelude?: string;
  /** HTML badge shown next to a policy name (already escaped). */
  policyBadge?: (cp: CellPolicy) => string;
}

function renderCell(
  ctx: Ctx,
  t: TableRules,
  cell: Cell,
  options: CellOptions = { id: anchorId("c", t.name, cell.operation), title: `${t.name} / ${cell.operation}` }
): string {
  return `<section class="cell-detail" id="${options.id}">
<h3>${esc(options.title)}</h3>
${options.prelude ?? ""}
${renderPolicyTable(ctx, cell, options.policyBadge)}
${renderCellPolicyFunctions(ctx, cell)}
<h4>Effective rule per role</h4>
${t.rls.enabled ? "" : '<p class="danger-text">RLS is disabled, so no policy is evaluated (only GRANTs apply).</p>'}
<div class="roles">${cell.roles.map((r) => renderRole(ctx, t, cell.operation, r)).join("")}</div>
<h4>Evaluation order</h4>
${renderEvaluationOrder(ctx, t, cell)}
</section>`;
}

function renderPolicyTable(ctx: Ctx, cell: Cell, policyBadge: (cp: CellPolicy) => string = () => ""): string {
  if (!cell.policies.length) return '<p class="muted">No policy applies to this operation.</p>';
  const op = cell.operation;
  const showUsing = op !== "INSERT";
  const showCheck = op === "INSERT" || op === "UPDATE";
  const head = `<tr><th>Policy</th><th>Roles</th><th>Type</th>${
    showUsing ? `<th>USING${op === "UPDATE" ? " (target rows)" : ""}</th>` : ""
  }${showCheck ? `<th>WITH CHECK${op === "UPDATE" ? " (new rows)" : ""}</th>` : ""}</tr>`;
  const rows = cell.policies
    .map(
      (cp) => `<tr>
<td>${esc(cp.policy.name)}${cp.fromAll ? ' <span class="badge" title="A FOR ALL policy expanded into this operation">from ALL</span>' : ""}${policyBadge(cp)}</td>
<td>${cp.policy.roles.map(esc).join(", ")}</td>
<td>${cp.policy.permissive ? '<span class="badge ok">PERMISSIVE</span>' : '<span class="badge warn">RESTRICTIVE</span>'}</td>
${showUsing ? `<td>${policyExpression(ctx, cp, "using")}</td>` : ""}
${showCheck ? `<td>${withCheckCell(ctx, cp, showUsing)}</td>` : ""}
</tr>`
    )
    .join("");
  return `<div class="scroll"><table class="policies"><thead>${head}</thead><tbody>${rows}</tbody></table></div>`;
}

/**
 * Rules of the functions called from the expressions this cell evaluates. Listed once per cell, not under every
 * policy or role, because the same helper is usually called by many policies.
 */
function renderCellPolicyFunctions(ctx: Ctx, cell: Cell): string {
  const op = cell.operation;
  const refs = new Map<string, PolicyFunctionRef>();
  const add = (sql: string | null, label: string) => {
    if (sql === null) return;
    for (const name of ctx.policyCalls(sql)) {
      const ref = refs.get(name) ?? { name, usedBy: [] };
      if (!ref.usedBy.includes(label)) ref.usedBy.push(label);
      refs.set(name, ref);
    }
  };
  for (const cp of cell.policies) {
    if (op !== "INSERT" && !cp.usingOmitted) add(cp.using, `${cp.policy.name} (USING)`);
    if ((op === "INSERT" || op === "UPDATE") && !cp.withCheckOmitted) {
      add(cp.withCheck, `${cp.policy.name} (WITH CHECK)`);
    }
  }
  return renderPolicyFunctions(ctx.rules, [...refs.values()]);
}

/**
 * WITH CHECK column of the policy table. A WITH CHECK written identically to the USING next to it is not split again;
 * this is separate from an omitted WITH CHECK, where PostgreSQL reuses USING.
 */
function withCheckCell(ctx: Ctx, cp: CellPolicy, usingShown: boolean): string {
  if (cp.withCheckFromUsing) {
    return `<p class="note">No WITH CHECK: the USING expression is reused</p>${policyExpression(ctx, cp, "withCheck")}`;
  }
  if (usingShown && !cp.usingOmitted && !cp.withCheckOmitted && cp.withCheck !== null && cp.withCheck === cp.using) {
    return '<span class="badge" title="The WITH CHECK expression is written identically to USING">same as USING</span>';
  }
  return policyExpression(ctx, cp, "withCheck");
}

function renderRole(ctx: Ctx, t: TableRules, op: Operation, r: RoleComposition): string {
  const title = `<h5>${esc(r.role)}</h5>`;
  if (!r.hasGrant) {
    return `<div class="role">${title}<p><span class="badge">no GRANT</span> Fails with a permission error (no ${op} privilege).</p></div>`;
  }
  if (r.bypassRls) {
    return `<div class="role">${title}<p><span class="badge warn">bypasses RLS</span> Has BYPASSRLS, so policies are not evaluated and every row is allowed.</p></div>`;
  }
  if (!t.rls.enabled) {
    return `<div class="role">${title}<p><span class="badge danger">RLS off</span> Every row is allowed.</p></div>`;
  }
  if (r.deniedByDefault) {
    const why = r.deniedByRestrictive?.length
      ? `RESTRICTIVE ${r.deniedByRestrictive.map(esc).join(", ")} ${
          r.deniedByRestrictive.length > 1 ? "are" : "is"
        } scoped to other buckets and always false for objects in this bucket`
      : r.permissive.length
        ? "The PERMISSIVE policies that apply omit the expression this operation needs"
        : "No PERMISSIVE policy applies";
    return `<div class="role">${title}<p><span class="badge danger">denied by default</span> ${why}, so ${
      op === "INSERT" ? "no row can be inserted" : "no row is visible or targetable"
    }.</p></div>`;
  }
  const blocks: string[] = [];
  if (op !== "INSERT") {
    blocks.push(
      renderComposition(ctx, r, "using", op === "UPDATE" ? "Target rows (USING)" : "Visible / target rows (USING)")
    );
  }
  if (op === "INSERT" || op === "UPDATE") {
    blocks.push(
      renderComposition(ctx, r, "withCheck", op === "UPDATE" ? "New rows (WITH CHECK)" : "Inserted rows (WITH CHECK)")
    );
  }
  return `<div class="role">${title}${blocks.join("")}</div>`;
}

/**
 * A policy expression as evaluated in this cell. PostgreSQL skips an omitted expression when combining policies,
 * so it is labelled by its effect instead of being shown as an empty or `true` condition.
 */
function policyExpression(ctx: Ctx, cp: CellPolicy, key: "using" | "withCheck"): string {
  const omitted = key === "using" ? cp.usingOmitted : cp.withCheckOmitted;
  if (!omitted) return renderExpression(ctx, cp[key]);
  const clause = key === "using" ? "USING" : "WITH CHECK";
  const effect = cp.policy.permissive
    ? key === "using"
      ? "this policy grants no rows"
      : "this policy allows no rows"
    : "no restriction from this policy";
  return `<span class="badge warn">${clause} omitted</span> <span class="muted">${effect}</span>`;
}

function renderComposition(ctx: Ctx, r: RoleComposition, key: "using" | "withCheck", label: string): string {
  const item = (cp: CellPolicy) =>
    `<li><span class="pname">${esc(cp.policy.name)}</span>${cp.fromAll ? ' <span class="badge">from ALL</span>' : ""}${
      key === "withCheck" && cp.withCheckFromUsing ? ' <span class="badge">reuses USING</span>' : ""
    }${policyExpression(ctx, cp, key)}</li>`;
  const restrictive = r.restrictive.length
    ? `<div class="and-join">AND</div><div class="grp and"><div class="op-label">RESTRICTIVE (all must pass = AND)</div><ul>${r.restrictive
        .map(item)
        .join("")}</ul></div>`
    : "";
  return `<div class="composition"><div class="clabel">${esc(label)}</div>
<div class="grp or"><div class="op-label">PERMISSIVE (any one passes = OR)</div><ul>${r.permissive.map(item).join("")}</ul></div>
${restrictive}</div>`;
}

/** Renders a policy expression split into AND / OR groups, with pattern tags on each condition. */
export function renderExpression(ctx: Pick<Ctx, "tags" | "linkFunction">, sql: string | null): string {
  if (sql === null) return '<span class="muted">(none)</span>';
  const tree = parseCondition(sql);
  const tagsHtml = (s: string) =>
    matchTags(s, ctx.tags)
      .map((tag) => `<span class="tag" title="${esc(tag.description)}">${esc(tag.label)}</span>`)
      .join("");
  const node = (n: ConditionNode): string => {
    if (n.kind === "raw") {
      return `<div class="cond raw"><span class="badge">could not split; original SQL</span>${tagsHtml(n.sql)}<pre><code>${highlightSql(
        n.sql,
        ctx.linkFunction
      )}</code></pre></div>`;
    }
    if (n.kind === "leaf") {
      return `<div class="cond"><code>${highlightSql(n.sql, ctx.linkFunction)}</code>${tagsHtml(n.sql)}</div>`;
    }
    const label = n.kind === "and" ? "all of (AND)" : "any of (OR)";
    return `<div class="grp ${n.kind}"><div class="op-label">${label}</div>${n.children.map(node).join("")}</div>`;
  };
  const rendered = node(tree);
  return `${rendered}${
    leaves(tree).length > 1
      ? `<details class="src"><summary>Original SQL</summary><pre><code>${highlightSql(sql, ctx.linkFunction)}</code></pre></details>`
      : ""
  }`;
}

function renderTriggerList(ctx: Ctx, triggers: Trigger[]): string {
  if (!triggers.length) return ' <span class="muted">none</span>';
  return `<ul class="triggers">${triggers
    .map((tr) => {
      const fnHref = tr.function.schema === ctx.doc.source.schema ? ctx.linkFunction(tr.function.name) : null;
      const fnName = esc(`${tr.function.schema}.${tr.function.name}`);
      return `<li><b>${esc(tr.name)}</b> <span class="badge">${esc(tr.timing)}</span> <span class="badge">${
        tr.level === "ROW" ? "FOR EACH ROW" : "FOR EACH STATEMENT"
      }</span> <span class="badge">${esc(tr.events.join(" | "))}</span>${
        tr.enabled === "D" ? ' <span class="badge danger">disabled</span>' : ""
      }${tr.isConstraintTrigger ? ' <span class="badge">CONSTRAINT</span>' : ""}${
        tr.function.securityDefiner ? ' <span class="badge warn">SECURITY DEFINER</span>' : ""
      }
<div>Function: ${fnHref ? `<a href="${esc(fnHref)}">${fnName}</a>` : fnName}</div>
${tr.updateColumns.length ? `<div>UPDATE OF: ${tr.updateColumns.map(esc).join(", ")}</div>` : ""}
${tr.when ? `<div>WHEN: ${renderExpression(ctx, tr.when)}</div>` : ""}
<details class="src"><summary>Definition</summary><pre><code>${highlightSql(tr.definition, ctx.linkFunction)}</code></pre></details>
${triggerFunctionRules(ctx, tr)}</li>`;
    })
    .join("")}</ul>`;
}

function triggerFunctionRules(ctx: Ctx, tr: Trigger): string {
  if (tr.function.schema !== ctx.doc.source.schema) return "";
  const fn = ctx.rules.functionOf(tr.function.name);
  return fn ? renderFunctionRules(ctx.rules, fn, true) : "";
}

function renderCascades(ctx: Ctx, effects: CascadeEffect[]): string {
  if (!effects.length) return ' <span class="muted">no foreign key references this table</span>';
  const item = (e: CascadeEffect): string => {
    const name =
      e.schema === ctx.doc.source.schema
        ? `<a href="#${anchorId("t", e.table)}">${esc(e.table)}</a>`
        : esc(`${e.schema}.${e.table}`);
    const result =
      e.resultingOperation === "BLOCK"
        ? '<span class="badge warn">rejected while referencing rows exist</span>'
        : e.resultingOperation === "DELETE"
          ? '<span class="badge danger">deletes child rows</span>'
          : '<span class="badge warn">updates child rows</span>';
    return `<li>${name} (${esc(e.columns.join(", "))} / ${esc(e.constraint)}) <span class="badge">${esc(e.action)}</span> ${result}${
      e.cycle ? ' <span class="badge danger">cycle (stopped here)</span>' : ""
    }${e.children.length ? `<ul>${e.children.map(item).join("")}</ul>` : ""}</li>`;
  };
  return `<ul class="cascade">${effects.map(item).join("")}</ul>`;
}

function renderEvaluationOrder(ctx: Ctx, t: TableRules, cell: Cell): string {
  const op = cell.operation;
  const steps: string[] = [];
  steps.push(`<li><b>GRANT</b>: the role must hold the ${op} privilege (otherwise a permission error)</li>`);
  if (op === "SELECT") {
    steps.push("<li><b>USING</b>: only rows matching the effective rule are visible</li>");
    return `<ol class="order">${steps.join("")}</ol>`;
  }
  if (op === "UPDATE" || op === "DELETE") {
    steps.push(
      "<li><b>USING</b>: narrows the target rows (non-matching rows are silently skipped). With WHERE / RETURNING, SELECT policies are evaluated too</li>"
    );
  }
  if (cell.insteadTriggers.length) {
    steps.push(`<li><b>INSTEAD OF triggers</b>${renderTriggerList(ctx, cell.insteadTriggers)}</li>`);
  }
  steps.push(`<li><b>BEFORE triggers</b> (statement, then row)${renderTriggerList(ctx, cell.beforeTriggers)}</li>`);
  if (op === "INSERT" || op === "UPDATE") {
    steps.push(
      "<li><b>WITH CHECK</b>: the new row, after BEFORE triggers, must satisfy the effective rule or an error is raised</li>"
    );
    steps.push(`<li><b>Constraints</b>${renderConstraintSummary(ctx, t)}</li>`);
  }
  if (op === "DELETE" || op === "UPDATE") {
    steps.push(
      `<li><b>Foreign key actions</b> (effect on referencing tables)${renderCascades(ctx, cell.cascades)}</li>`
    );
  }
  steps.push(`<li><b>AFTER triggers</b> (row, then statement)${renderTriggerList(ctx, cell.afterTriggers)}</li>`);
  return `<ol class="order">${steps.join("")}</ol>`;
}

function renderConstraintSummary(ctx: Ctx, t: TableRules): string {
  const notNull = t.columns.filter((c) => c.notNull).map((c) => esc(c.name));
  return `<div class="muted">NOT NULL: ${notNull.length ? notNull.join(", ") : "none"}</div>${renderConstraintList(ctx, t)}`;
}

/* ---------- Functions (RPC) ---------- */

/** A SECURITY DEFINER function deserves review when its search_path is not pinned or anon can execute it. */
export function isSecdefWarning(f: FunctionInfo): boolean {
  return f.securityDefiner && (f.searchPath === null || f.executableBy.anon);
}

function renderFunctions(ctx: Ctx): string {
  const fns = ctx.doc.functions;
  const secdef = fns.filter((f) => f.securityDefiner);
  const noPath = secdef.filter((f) => f.searchPath === null).length;
  const anon = secdef.filter((f) => f.executableBy.anon).length;
  const rows = fns
    .map((f, i) => {
      const id = anchorId("fn", f.name, String(i));
      const warn: string[] = [];
      if (f.securityDefiner && f.searchPath === null)
        warn.push('<span class="badge danger">search_path not set</span>');
      if (f.securityDefiner && f.executableBy.anon) warn.push('<span class="badge danger">executable by anon</span>');
      return `<article class="fn${isSecdefWarning(f) ? " fn-warn" : ""}${f.securityDefiner ? " fn-secdef" : ""}" id="${id}" data-name="${esc(
        f.name
      )}">
<h3>${esc(f.name)}(${esc(f.identityArguments)}) <small>→ ${esc(f.returns)}</small></h3>
<p>${f.securityDefiner ? '<span class="badge warn">SECURITY DEFINER</span>' : '<span class="badge">SECURITY INVOKER</span>'}
<span class="badge">${esc(f.language)}</span> <span class="badge">${esc(f.volatility)}</span>
${f.searchPath !== null ? `<span class="badge ok">search_path=${esc(f.searchPath)}</span>` : ""}
<span class="badge${f.executableBy.anon ? " warn" : ""}">anon: ${f.executableBy.anon ? "can execute" : "cannot execute"}</span>
<span class="badge">authenticated: ${f.executableBy.authenticated ? "can execute" : "cannot execute"}</span> ${warn.join(" ")}</p>
${
  ctx.rules.functionOf(f.name) === f
    ? renderFunctionRules(ctx.rules, f, false)
    : '<p class="note">Rules are shown for only one overload with this name (the one without arguments, if any); the definition of this overload is below.</p>'
}
${
  f.definition
    ? `<details class="src"><summary>Definition</summary><pre><code>${highlightSql(f.definition, ctx.linkFunction)}</code></pre></details>`
    : ""
}
</article>`;
    })
    .join("\n");
  return `<h2>Functions (RPC)</h2>
<p>${secdef.length} SECURITY DEFINER functions (${noPath} without search_path, ${anon} executable by anon).
SECURITY DEFINER functions run with the owner's privileges and can bypass RLS; check that search_path is pinned and EXECUTE is restricted.</p>
<p><label><input type="checkbox" id="fn-secdef-only"> SECURITY DEFINER only</label>
<label><input type="checkbox" id="fn-warn-only"> Warnings only</label></p>
<div id="fn-list">${rows}</div>`;
}

/* ---------- Storage ---------- */

/** Formats a byte count, keeping the exact value (e.g. `52428800 bytes (50 MiB)`). */
export function formatBytes(n: number): string {
  const units = ["KiB", "MiB", "GiB", "TiB"];
  let v = n;
  let unit = "";
  for (const u of units) {
    if (v < 1024) break;
    v /= 1024;
    unit = u;
  }
  const short = unit ? ` (${Number.isInteger(v) ? v : v.toFixed(1)} ${unit})` : "";
  return `${n} bytes${short}`;
}

function renderStorage(ctx: Ctx): string {
  const storage = ctx.doc.storage;
  if (!storage) {
    return '<h2>Storage</h2><p class="muted">Storage was not extracted: the database has no storage schema, or rules.json was written by an older version.</p>';
  }
  const objects = storage.objects;
  // Without read access to storage.buckets the settings are unknown; the buckets named by policies still get cells
  const buckets: { id: string; info: BucketInfo | null }[] = storage.bucketsReadable
    ? storage.buckets.map((b) => ({ id: b.id, info: b }))
    : objects
      ? bucketIdsInPolicies(objects).map((id) => ({ id, info: null }))
      : [];
  const unreadable = storage.bucketsReadable
    ? ""
    : '<p class="note">The extracting role could not read storage.buckets, so bucket settings are unknown and only the buckets named by policies are listed. storage.buckets has row level security enabled: besides USAGE on the storage schema and SELECT on its id, name, public, file_size_limit and allowed_mime_types columns, the role needs BYPASSRLS (or a PERMISSIVE SELECT policy on storage.buckets that applies to it) to include them.</p>';
  const filtered =
    storage.bucketsReadable && storage.bucketsFiltered
      ? '<p class="note">storage.buckets was read through its row level security policies, so only the buckets visible to the extracting role are listed; others may exist. Policies naming a hidden bucket are listed below as naming buckets that are not visible to the extracting role.</p>'
      : "";
  const publicCount = storage.buckets.filter((b) => b.public).length;
  const settings = !storage.bucketsReadable
    ? ""
    : storage.buckets.length
      ? `<div class="scroll"><table class="plain"><thead><tr><th>Bucket</th><th>Name</th><th>Public</th><th>File size limit</th><th>Allowed MIME types</th></tr></thead><tbody>${storage.buckets
          .map(
            (
              b
            ) => `<tr class="${b.public ? "row-danger" : ""}"><th><a href="#${anchorId("b", b.id)}">${esc(b.id)}</a></th>
<td>${esc(b.name)}</td>
<td>${b.public ? '<span class="badge danger">public</span>' : '<span class="badge ok">private</span>'}</td>
<td>${b.fileSizeLimit === null ? '<span class="muted">no limit</span>' : esc(formatBytes(b.fileSizeLimit))}</td>
<td>${b.allowedMimeTypes === null ? '<span class="muted">any</span>' : b.allowedMimeTypes.map((m) => `<code>${esc(m)}</code>`).join(", ")}</td></tr>`
          )
          .join("")}</tbody></table></div>`
      : '<p class="muted">No buckets.</p>';
  const publicNote = publicCount
    ? `<p class="danger-text">${publicCount} public bucket(s): anyone who knows an object's URL can download it without any policy check. The SELECT policies below apply only to the authenticated Storage API.</p>`
    : "";
  if (!objects) {
    return `<h2>Storage</h2>${publicNote}${unreadable}${filtered}<h3>Bucket settings</h3>${settings}<p class="muted">storage.objects does not exist, so there are no object rules.</p>`;
  }
  const cells = new Map<string, BucketCell[]>(
    buckets.map((b) => [b.id, OPERATIONS.map((op) => buildBucketCell(ctx.doc, objects, b.id, op))])
  );
  const head = `<tr><th>Bucket</th>${OPERATIONS.map((op) => `<th>${op}</th>`).join("")}</tr>`;
  const rows = buckets
    .map(
      (b) =>
        `<tr class="${b.info?.public ? "row-danger" : ""}"><th><a href="#${anchorId("b", b.id)}">${esc(b.id)}</a>${
          b.info?.public ? ' <span class="badge danger">public</span>' : ""
        }</th>${(cells.get(b.id) ?? [])
          .map((c) => `<td>${renderMatrixCell(ctx, objects, c, `#${anchorId("s", b.id, c.operation)}`)}</td>`)
          .join("")}</tr>`
    )
    .join("\n");
  const unknown = storage.bucketsReadable ? unknownBucketReferences(objects, storage.buckets) : [];
  const unknownHtml = unknown.length
    ? `<p class="note">Policies naming buckets that ${
        storage.bucketsFiltered ? "are not visible to the extracting role" : "do not exist"
      }: ${unknown.map((u) => `${esc(u.policy)} → <code>${esc(u.bucket)}</code>`).join(", ")}</p>`
    : "";
  const rls = objects.rls.enabled
    ? '<span class="badge ok">enabled</span>'
    : '<span class="badge danger">disabled</span> <span class="danger-text">Every role holding a GRANT can access every object.</span>';
  const bucketSections = buckets
    .map((b) => {
      const info = b.info;
      const summary = info
        ? `<p>${info.public ? '<span class="badge danger">public</span> ' : '<span class="badge ok">private</span> '}size limit: ${
            info.fileSizeLimit === null ? "none" : esc(formatBytes(info.fileSizeLimit))
          } / MIME types: ${info.allowedMimeTypes === null ? "any" : info.allowedMimeTypes.map(esc).join(", ")}</p>`
        : '<p class="muted">Bucket settings unknown (storage.buckets was not readable).</p>';
      const details = (cells.get(b.id) ?? [])
        .map((c) => {
          const common = c.sharedPolicies.filter((p) => p.reason !== "outOfBucket");
          const outside = c.sharedPolicies.filter((p) => p.reason === "outOfBucket");
          const shared = `${
            common.length
              ? `<p class="note">Shared by every bucket (no bucket condition): ${common
                  .map(
                    (p) => `${esc(p.name)}${p.reason === "unrecognized" ? " (bucket condition not recognized)" : ""}`
                  )
                  .join(", ")}</p>`
              : ""
          }${
            outside.length
              ? `<p class="danger-text">RESTRICTIVE policies scoped to other buckets are always false here, so they deny this operation: ${outside
                  .map((p) => esc(p.name))
                  .join(", ")}</p>`
              : ""
          }`;
          const sharedNames = new Map(c.sharedPolicies.map((p) => [p.name, p.reason]));
          return renderCell(ctx, objects, c, {
            id: anchorId("s", b.id, c.operation),
            title: `${b.id} / ${c.operation}`,
            prelude: `${summary}${shared}`,
            policyBadge: (cp) => {
              const reason = sharedNames.get(cp.policy.name);
              if (reason === undefined) return "";
              if (reason === "outOfBucket") {
                return ' <span class="badge danger" title="RESTRICTIVE and scoped to other buckets: its bucket condition is false for every object here">always false in this bucket</span>';
              }
              return reason === "unrecognized"
                ? ' <span class="badge warn" title="bucket_id is used in a form that is not read; shown in every bucket">all buckets?</span>'
                : ' <span class="badge" title="No bucket condition: applies to every bucket">all buckets</span>';
            }
          });
        })
        .join("");
      return `<article class="table-detail" id="${anchorId("b", b.id)}" data-name="${esc(b.id)}"><h2>${esc(b.id)}</h2>${details}</article>`;
    })
    .join("");
  return `<h2>Storage</h2>
${publicNote}
${unreadable}${filtered}
${settings ? `<h3>Bucket settings</h3>${settings}` : ""}
<h3>Buckets × operations (storage.objects)</h3>
<p>RLS on storage.objects: ${rls}. Policies are assigned to a bucket by their <code>bucket_id</code> conditions
(<code>bucket_id = '…'</code>, <code>bucket_id IN (…)</code>); a policy without one applies to every bucket and is marked <span class="badge">all buckets</span>.</p>
<p class="legend">Same legend as Tables × operations (counts for <b>authenticated</b>); in a bucket, <span class="badge danger">deny</span> also means a RESTRICTIVE policy scoped to other buckets. Click a cell to jump to its details.</p>
${unknownHtml}
<div class="scroll"><table class="matrix"><thead>${head}</thead><tbody>${rows}</tbody></table></div>
${bucketSections}`;
}

/* ---------- Views ---------- */

function renderViews(ctx: Ctx): string {
  if (!ctx.doc.views.length) return '<h2>Views</h2><p class="muted">No views.</p>';
  const items = ctx.doc.views
    .map((v) => {
      const status =
        v.kind === "materialized"
          ? '<span class="badge danger">materialized view</span> RLS does not apply. Any role with a GRANT can read every stored row.'
          : v.securityInvoker
            ? '<span class="badge ok">security_invoker=true</span> Runs as the calling role and follows the RLS of the base tables.'
            : '<span class="badge danger">security_invoker not set</span> Reads the base tables with the view owner\'s privileges, so it may bypass their RLS.';
      const bases = v.baseRelations
        .map((b) =>
          b.schema === ctx.doc.source.schema
            ? `<a href="#${anchorId("t", b.name)}">${esc(b.name)}</a>`
            : esc(`${b.schema}.${b.name}`)
        )
        .join(", ");
      return `<article id="${anchorId("v", v.name)}"><h3>${esc(v.name)}</h3><p>${status}${
        v.securityBarrier ? ' <span class="badge">security_barrier</span>' : ""
      }</p><p>Base relations: ${bases || '<span class="muted">none</span>'}</p>
<details class="src"><summary>Definition</summary><pre><code>${highlightSql(v.definition, ctx.linkFunction)}</code></pre></details></article>`;
    })
    .join("");
  return `<h2>Views</h2>${items}`;
}

/* ---------- Excluded & reference ---------- */

function renderMeta(doc: RulesDocument): string {
  const ex = doc.excluded;
  return `<h2>Excluded objects</h2>
<ul>
<li>Functions owned by extensions: ${count(ex.extensionOwnedFunctions)} (pg_depend deptype='e')</li>
<li>Tables and views owned by extensions: ${count(ex.extensionOwnedRelations)}</li>
<li>Platform event triggers: ${ex.eventTriggers.length}
<ul>${ex.eventTriggers.map((e) => `<li>${esc(e.name)} — ${esc(e.reason)}</li>`).join("")}</ul></li>
</ul>
<h2>Reference</h2>
<h3>Roles</h3>
<ul>${doc.roles
    .map(
      (r) =>
        `<li>${esc(r.name)}${r.bypassRls ? ' <span class="badge warn">BYPASSRLS</span>' : ""}${
          r.superuser ? ' <span class="badge warn">SUPERUSER</span>' : ""
        }</li>`
    )
    .join("")}</ul>
<h3>User-defined event triggers</h3>
${
  doc.eventTriggers.length
    ? `<ul>${doc.eventTriggers.map((e) => `<li>${esc(e.name)} (owner ${esc(e.owner)})</li>`).join("")}</ul>`
    : '<p class="muted">none</p>'
}
<h3>Foreign keys from other schemas</h3>
${
  doc.externalForeignKeys.length
    ? `<ul>${doc.externalForeignKeys
        .map(
          (f) =>
            `<li>${esc(`${f.from.schema}.${f.from.table}`)} → ${esc(f.references.table)} (ON DELETE ${esc(f.onDelete)} / ON UPDATE ${esc(f.onUpdate)})</li>`
        )
        .join("")}</ul>`
    : '<p class="muted">none</p>'
}
<h3>Not covered</h3>
<p>The cron schema is not covered. Of the storage schema only storage.objects and the settings of storage.buckets are covered; the rules of storage-schema functions called by triggers are not analyzed.</p>`;
}
