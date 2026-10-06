/**
 * Renders the rules found in a function body (and in the functions it calls) for trigger cells and
 * function details. Shared by both places so the two views never disagree.
 */
import { collectCallTree, MAX_CALL_DEPTH } from "../model/plpgsql.ts";
import type { FunctionAnalysis, FunctionInfo, GuardPathElement, RulesDocument } from "../model/types.ts";
import { escapeHtml as esc, highlightSql } from "./sql.ts";

export interface FunctionRulesCtx {
  doc: RulesDocument;
  linkFunction: (name: string) => string | null;
  /** Renders a condition (split into AND / OR, tagged, highlighted). */
  expression: (sql: string | null) => string;
  functionOf: (name: string) => FunctionInfo | undefined;
  analysisOf: (name: string) => FunctionAnalysis | undefined;
  /** More than one overload has this name, so a call by name may resolve to a different one than the analysis shown. */
  isOverloaded: (name: string) => boolean;
  tableHref: (schema: string | null, name: string) => string | null;
}

const fnLink = (ctx: FunctionRulesCtx, name: string): string => {
  const href = ctx.linkFunction(name);
  const label = `${esc(name)}()`;
  return href ? `<a href="${esc(href)}">${label}</a>` : label;
};

function renderPath(ctx: FunctionRulesCtx, path: GuardPathElement[]): string {
  const branches = path.filter((p) => p.kind !== "LOOP" || p.sql);
  if (!branches.length) return '<span class="badge warn">unconditional</span>';
  return `<ol class="path">${branches
    .map((p) => {
      const head =
        p.kind === "WHEN" && p.subject !== undefined
          ? `<code>CASE ${highlightSql(p.subject, ctx.linkFunction)}</code> WHEN`
          : esc(p.kind);
      const cond = p.sql === null ? "" : ctx.expression(p.sql);
      const prior = p.notTaken.length
        ? `<div class="muted">only after these earlier branches were false:</div><ul>${p.notTaken
            .map((s) => `<li><code>${highlightSql(s, ctx.linkFunction)}</code></li>`)
            .join("")}</ul>`
        : "";
      const comment = p.comment ? `<pre class="comment">${esc(p.comment)}</pre>` : "";
      return `<li>${comment}<span class="badge">${head}</span>${cond}${prior}</li>`;
    })
    .join("")}</ol>`;
}

/** A PL/pgSQL definition of at most this many lines is folded into a policy cell when the analysis found nothing in it. */
export const MAX_INLINE_BODY_LINES = 40;

/** Whether the analysis found any guard, early return, side effect or column reference. */
export function hasStructuralFindings(a: FunctionAnalysis): boolean {
  return (
    a.guards.length > 0 ||
    a.earlyReturns.length > 0 ||
    a.sideEffects.length > 0 ||
    a.newColumns.length > 0 ||
    a.oldColumns.length > 0 ||
    a.changeCheckedColumns.length > 0
  );
}

/**
 * Rules of one function body. `bodyShown` tells whether the full definition follows in the same place, so that a
 * body with no findings points the reader to it instead of reading as "no issue".
 */
export function renderAnalysis(ctx: FunctionRulesCtx, fn: FunctionInfo, a: FunctionAnalysis, bodyShown = true): string {
  const flags: string[] = [`<span class="badge">${esc(a.status)}</span>`];
  if (a.reason) flags.push(`<span class="muted">${esc(a.reason)}</span>`);
  if (a.dynamicSql) flags.push('<span class="badge warn">dynamic SQL not analyzed</span>');
  if (Number(a.unparsedCount) > 0) {
    flags.push(`<span class="badge warn">unparsed: ${esc(String(Number(a.unparsedCount) || "?"))}</span>`);
  }
  if (fn.securityDefiner) {
    flags.push('<span class="badge warn">SECURITY DEFINER</span>');
    if (fn.searchPath === null) flags.push('<span class="badge danger">search_path not set</span>');
  }
  const parts: string[] = [`<p class="flags">${flags.join(" ")}</p>`];

  const comments = [fn.comment ?? null, ...a.headerComments].filter((c): c is string => Boolean(c));
  if (comments.length) {
    parts.push(
      `<div class="sub">Comments</div>${comments.map((c) => `<pre class="comment">${esc(c)}</pre>`).join("")}`
    );
  }
  if (a.earlyReturns.length) {
    parts.push(
      `<div class="sub">Returns early (later rules are skipped)</div><ul class="guards">${a.earlyReturns
        .map(
          (r) =>
            `<li>${renderPath(ctx, r.path)}<div>→ <code>${highlightSql(r.statement, ctx.linkFunction)}</code></div></li>`
        )
        .join("")}</ul>`
    );
  }
  if (a.guards.length) {
    parts.push(
      `<div class="sub">Guards (condition → error)</div><ul class="guards">${a.guards
        .map((g) => {
          const message =
            g.message !== null
              ? `<q>${esc(g.message)}</q>`
              : '<span class="muted">(no message: re-raise or condition name)</span>';
          const extra = [
            g.arguments ? `args: <code>${highlightSql(g.arguments, ctx.linkFunction)}</code>` : "",
            g.errcode ? `ERRCODE <code>${esc(g.errcode)}</code>` : "",
            g.detail ? `DETAIL ${esc(g.detail)}` : "",
            g.hint ? `HINT ${esc(g.hint)}` : ""
          ].filter(Boolean);
          return `<li>${renderPath(ctx, g.path)}<div class="raise">→ RAISE EXCEPTION ${message}${
            extra.length ? ` <span class="muted">${extra.join(" / ")}</span>` : ""
          }</div></li>`;
        })
        .join("")}</ul>`
    );
  }
  if (a.sideEffects.length) {
    parts.push(
      `<div class="sub">Side effects</div><ul>${a.sideEffects
        .map((s) => {
          const qualified = s.schema ? `${s.schema}.${s.name}` : s.name;
          let target = esc(qualified);
          if (s.operation === "PERFORM") {
            const href = s.schema === null || s.schema === ctx.doc.source.schema ? ctx.linkFunction(s.name) : null;
            target = href ? `<a href="${esc(href)}">${esc(qualified)}()</a>` : `${esc(qualified)}()`;
          } else {
            const href = ctx.tableHref(s.schema, s.name);
            if (href) target = `<a href="${esc(href)}">${esc(qualified)}</a>`;
          }
          return `<li><span class="badge">${esc(s.operation)}</span> ${target}</li>`;
        })
        .join("")}</ul>`
    );
  }
  const cols = (label: string, list: string[]) =>
    list.length ? `<div>${esc(label)}: ${list.map((c) => `<code>${esc(c)}</code>`).join(", ")}</div>` : "";
  const colHtml =
    cols("Columns checked for change (NEW vs OLD)", a.changeCheckedColumns) +
    cols("NEW.*", a.newColumns) +
    cols("OLD.*", a.oldColumns);
  if (colHtml) parts.push(`<div class="sub">Referenced columns</div>${colHtml}`);
  if (a.calledFunctions.length) {
    parts.push(`<div class="sub">Calls</div><p>${a.calledFunctions.map((n) => fnLink(ctx, n)).join(", ")}</p>`);
  }
  if (!hasStructuralFindings(a) && a.status !== "unsupported") {
    parts.push(
      `<p class="note">No structural conditions were detected by the analysis; ${
        bodyShown ? "review the body below" : "see the full definition"
      }.</p>`
    );
  }
  return parts.join("");
}

/** A function called from the policy expressions of one cell, with the expressions that call it. */
export interface PolicyFunctionRef {
  name: string;
  /** Labels such as `policy name (USING)`. */
  usedBy: string[];
}

/**
 * Rules of the functions called from the policies of one cell, each folded and listed once per cell.
 * A PL/pgSQL body stays in the function detail (linked); a SQL body, or one that could not be analyzed, is folded in.
 */
export function renderPolicyFunctions(ctx: FunctionRulesCtx, refs: PolicyFunctionRef[]): string {
  // Each body is folded in at most once per cell, even when several listed functions reach the same helper
  const shownBodies = new Set<string>();
  const items = refs
    .map((ref) => {
      const fn = ctx.functionOf(ref.name);
      if (!fn) return "";
      const analysis = ctx.analysisOf(ref.name);
      // A PL/pgSQL body without findings has no summary to read, so a short one is folded in; a long one stays linked
      const quietShortBody =
        analysis !== undefined &&
        !hasStructuralFindings(analysis) &&
        fn.definition !== null &&
        fn.definition.split("\n").length <= MAX_INLINE_BODY_LINES;
      const withDefinition =
        !shownBodies.has(fn.name) &&
        (fn.language === "sql" || analysis === undefined || analysis.status === "failed" || quietShortBody);
      const rules =
        renderFunctionRules(ctx, fn, withDefinition, { rootBodyShown: withDefinition, shownBodies }) ||
        (fn.definition
          ? `<pre><code>${highlightSql(fn.definition, ctx.linkFunction)}</code></pre>`
          : '<p class="muted">No definition available.</p>');
      const href = ctx.linkFunction(ref.name);
      const definitionLink =
        !withDefinition && href
          ? `<p class="muted">Full definition: <a href="${esc(href)}">${esc(ref.name)}()</a></p>`
          : "";
      const badges = [
        `<span class="badge">${esc(fn.language)}</span>`,
        fn.securityDefiner ? '<span class="badge warn">SECURITY DEFINER</span>' : "",
        ctx.isOverloaded(ref.name)
          ? '<span class="badge warn" title="Rules are shown for one overload with this name">overloaded</span>'
          : ""
      ].filter(Boolean);
      return `<details class="pfn"><summary>${fnLink(ctx, ref.name)} ${badges.join(" ")} <span class="muted">used by ${ref.usedBy
        .map(esc)
        .join(", ")}</span></summary>${rules}${definitionLink}</details>`;
    })
    .filter(Boolean);
  return items.length ? `<h4>Functions called by these policies</h4><div class="pfns">${items.join("")}</div>` : "";
}

/**
 * Rules of a function plus the rules of every function it reaches through calls, labelled "via ...".
 * `withDefinition` adds the folded full definitions (the function tab already shows the root's).
 */
export interface FunctionRulesOptions {
  /** The root's full definition is shown with these rules (here or right below them). Default true. */
  rootBodyShown?: boolean;
  /** Names whose definitions were already folded in nearby; they are not repeated. */
  shownBodies?: Set<string>;
}

export function renderFunctionRules(
  ctx: FunctionRulesCtx,
  root: FunctionInfo,
  withDefinition: boolean,
  options: FunctionRulesOptions = {}
): string {
  const rootAnalysis = ctx.analysisOf(root.name);
  if (!rootAnalysis) return "";
  const tree = collectCallTree(root.name, ctx.analysisOf);
  const definition = (f: FunctionInfo) => {
    if (options.shownBodies?.has(f.name)) return "";
    options.shownBodies?.add(f.name);
    return f.definition
      ? `<details class="src"><summary>Full definition of ${esc(f.name)}()</summary><pre><code>${highlightSql(
          f.definition,
          ctx.linkFunction
        )}</code></pre></details>`
      : "";
  };
  const helpers = tree.entries
    .filter((e) => e.depth > 0)
    .map((e) => {
      const fn = ctx.functionOf(e.name);
      if (!fn) return "";
      const chain = e.via
        .map((n) => `${fnLink(ctx, n)}${ctx.isOverloaded(n) ? ' <span class="badge warn">overloaded</span>' : ""}`)
        .join(" → ");
      // A PL/pgSQL helper's full definition lives in its function detail (linked above) to keep each cell small;
      // a SQL helper has no other summary, so its body is shown here
      const body = fn.language === "sql" ? definition(fn) : "";
      return `<div class="helper"><div class="via">via ${chain}</div>${renderAnalysis(ctx, fn, e.analysis, fn.language === "sql")}${body}</div>`;
    })
    .join("");
  const truncated = tree.truncated.filter((t) => t.reason !== "visited");
  const truncatedHtml = truncated.length
    ? `<p class="note">truncated: ${truncated
        .map(
          (t) =>
            `${fnLink(ctx, t.from)} → ${fnLink(ctx, t.to)} (${
              t.reason === "cycle" ? "cycle" : `depth limit ${MAX_CALL_DEPTH}`
            })`
        )
        .join(", ")}</p>`
    : "";
  return `<div class="fn-rules"><p class="note">Summary from a deterministic reading of the body; the full definition is authoritative.</p>
<div class="sub">Rules in ${fnLink(ctx, root.name)}</div>${renderAnalysis(ctx, root, rootAnalysis, options.rootBodyShown ?? true)}${
    withDefinition ? definition(root) : ""
  }${helpers ? `<div class="sub">Rules found in called functions</div>${helpers}` : ""}${truncatedHtml}</div>`;
}
