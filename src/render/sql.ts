/**
 * A small splitter that breaks pg_get_expr output on top-level AND / OR, plus SQL highlighting.
 * Not a general SQL parser: it only tracks parentheses, quotes and CASE ... END, and gives up
 * (returning the original text) when they do not balance.
 */

export type ConditionNode =
  | { kind: "and" | "or"; children: ConditionNode[] }
  | { kind: "leaf"; sql: string }
  /** An expression that could not be split (e.g. unbalanced parentheses); shown as the original SQL. */
  | { kind: "raw"; sql: string };

interface Token {
  kind: "string" | "ident" | "quoted" | "number" | "punct" | "space" | "other";
  text: string;
}

const KEYWORDS = new Set([
  "AND",
  "OR",
  "NOT",
  "IN",
  "IS",
  "NULL",
  "TRUE",
  "FALSE",
  "SELECT",
  "FROM",
  "WHERE",
  "AS",
  "EXISTS",
  "ANY",
  "ALL",
  "SOME",
  "ARRAY",
  "CASE",
  "WHEN",
  "THEN",
  "ELSE",
  "END",
  "LIKE",
  "ILIKE",
  "SIMILAR",
  "BETWEEN",
  "DISTINCT",
  "JOIN",
  "LEFT",
  "RIGHT",
  "INNER",
  "OUTER",
  "ON",
  "USING",
  "LIMIT",
  "ORDER",
  "BY",
  "GROUP",
  "HAVING",
  "UNION",
  "WITH",
  "CAST",
  "COALESCE",
  "OF",
  "NEW",
  "OLD"
]);

export function tokenize(sql: string): Token[] | null {
  const tokens: Token[] = [];
  let i = 0;
  while (i < sql.length) {
    const ch = sql[i] as string;
    if (/\s/.test(ch)) {
      let j = i + 1;
      while (j < sql.length && /\s/.test(sql[j] as string)) j++;
      tokens.push({ kind: "space", text: sql.slice(i, j) });
      i = j;
    } else if (ch === "'") {
      // E'...' with \' is not handled: pg_get_expr always escapes quotes as ''
      let j = i + 1;
      for (;;) {
        if (j >= sql.length) return null;
        if (sql[j] === "'") {
          if (sql[j + 1] === "'") j += 2;
          else break;
        } else j++;
      }
      tokens.push({ kind: "string", text: sql.slice(i, j + 1) });
      i = j + 1;
    } else if (ch === '"') {
      let j = i + 1;
      for (;;) {
        if (j >= sql.length) return null;
        if (sql[j] === '"') {
          if (sql[j + 1] === '"') j += 2;
          else break;
        } else j++;
      }
      tokens.push({ kind: "quoted", text: sql.slice(i, j + 1) });
      i = j + 1;
    } else if (/[A-Za-z_]/.test(ch)) {
      let j = i + 1;
      while (j < sql.length && /[A-Za-z0-9_$]/.test(sql[j] as string)) j++;
      tokens.push({ kind: "ident", text: sql.slice(i, j) });
      i = j;
    } else if (/[0-9]/.test(ch)) {
      let j = i + 1;
      while (j < sql.length && /[0-9.]/.test(sql[j] as string)) j++;
      tokens.push({ kind: "number", text: sql.slice(i, j) });
      i = j;
    } else if ("(),[]".includes(ch)) {
      tokens.push({ kind: "punct", text: ch });
      i++;
    } else {
      let j = i + 1;
      while (j < sql.length && /[^\sA-Za-z0-9_'"(),[\]]/.test(sql[j] as string)) j++;
      tokens.push({ kind: "other", text: sql.slice(i, j) });
      i = j;
    }
  }
  return tokens;
}

const upper = (t: Token) => (t.kind === "ident" ? t.text.toUpperCase() : "");

/** Computes the nesting depth (parentheses and CASE ... END) of each token; null when unbalanced. */
function depths(tokens: Token[]): number[] | null {
  const out: number[] = [];
  let depth = 0;
  for (const t of tokens) {
    if (t.kind === "punct" && (t.text === "(" || t.text === "[")) {
      out.push(depth);
      depth++;
      continue;
    }
    if (t.kind === "punct" && (t.text === ")" || t.text === "]")) {
      depth--;
      if (depth < 0) return null;
      out.push(depth);
      continue;
    }
    const u = upper(t);
    if (u === "CASE") {
      out.push(depth);
      depth++;
      continue;
    }
    if (u === "END") {
      depth--;
      if (depth < 0) return null;
      out.push(depth);
      continue;
    }
    out.push(depth);
  }
  return depth === 0 ? out : null;
}

function trimSpaces(tokens: Token[]): Token[] {
  let s = 0;
  let e = tokens.length;
  while (s < e && tokens[s]?.kind === "space") s++;
  while (e > s && tokens[e - 1]?.kind === "space") e--;
  return tokens.slice(s, e);
}

/** Removes parentheses that wrap the whole expression (only when the outer pair matches end to end). */
function stripOuterParens(tokens: Token[]): Token[] {
  let cur = trimSpaces(tokens);
  for (;;) {
    if (cur.length < 2 || cur[0]?.text !== "(" || cur[cur.length - 1]?.text !== ")") return cur;
    const d = depths(cur);
    if (!d) return cur;
    // The first ( must close at the very end (depth never returns to 0 in between)
    let closesAtEnd = true;
    for (let i = 1; i < cur.length - 1; i++) {
      if (d[i] === 0) {
        closesAtEnd = false;
        break;
      }
    }
    if (!closesAtEnd) return cur;
    const inner = trimSpaces(cur.slice(1, -1));
    // ( SELECT ... ) is a scalar subquery; keep its parentheses
    if (upper(inner[0] ?? { kind: "space", text: "" }) === "SELECT") return cur;
    cur = inner;
  }
}

function splitAt(tokens: Token[], keyword: "AND" | "OR"): Token[][] {
  const d = depths(tokens);
  if (!d) return [tokens];
  const parts: Token[][] = [];
  let start = 0;
  let pendingBetween = false;
  for (let i = 0; i < tokens.length; i++) {
    if (d[i] !== 0) continue;
    const u = upper(tokens[i] as Token);
    if (u === "BETWEEN") pendingBetween = true;
    if (u !== keyword) continue;
    // The AND in BETWEEN a AND b is not a logical operator
    if (keyword === "AND" && pendingBetween) {
      pendingBetween = false;
      continue;
    }
    parts.push(tokens.slice(start, i));
    start = i + 1;
  }
  parts.push(tokens.slice(start));
  return parts.map(trimSpaces);
}

const MAX_DEPTH = 8;

function build(tokens: Token[], level: number): ConditionNode {
  const body = stripOuterParens(tokens);
  const text = body.map((t) => t.text).join("");
  if (level >= MAX_DEPTH) return { kind: "leaf", sql: text };
  // AND binds tighter than OR, so split on OR first
  for (const kw of ["OR", "AND"] as const) {
    const parts = splitAt(body, kw);
    if (parts.length > 1) {
      if (parts.some((p) => p.length === 0)) return { kind: "raw", sql: text };
      return { kind: kw === "OR" ? "or" : "and", children: parts.map((p) => build(p, level + 1)) };
    }
  }
  return { kind: "leaf", sql: text };
}

/** Splits an expression into an AND / OR tree. Returns it as raw when tokens or parentheses do not balance. */
export function parseCondition(sql: string): ConditionNode {
  const tokens = tokenize(sql);
  if (!tokens || !depths(tokens)) return { kind: "raw", sql };
  return build(tokens, 0);
}

/** Lists the leaf conditions. */
export function leaves(node: ConditionNode): string[] {
  if (node.kind === "leaf" || node.kind === "raw") return [node.sql];
  return node.children.flatMap(leaves);
}

// Escapes all five HTML-significant characters (& < > " '); kept hand-written so the published package stays
// dependency-free.
// bearer:disable javascript_lang_manual_html_sanitization
export function escapeHtml(s: string): string {
  return s.replace(/[&<>"']/g, (c) =>
    c === "&" ? "&amp;" : c === "<" ? "&lt;" : c === ">" ? "&gt;" : c === '"' ? "&quot;" : "&#39;"
  );
}

/** Maps a function name to its anchor in the viewer, or null to leave it unlinked. */
export type FunctionLinker = (qualifiedName: string) => string | null;

/**
 * Converts SQL into highlighted HTML. Every token is escaped before being wrapped in a span,
 * so HTML in the input never passes through.
 */
export function highlightSql(sql: string, linkFunction: FunctionLinker = () => null): string {
  const tokens = tokenize(sql);
  if (!tokens) return escapeHtml(sql);
  let html = "";
  for (let i = 0; i < tokens.length; i++) {
    const t = tokens[i] as Token;
    const esc = escapeHtml(t.text);
    switch (t.kind) {
      case "string":
        html += `<span class="s">${esc}</span>`;
        break;
      case "number":
        html += `<span class="n">${esc}</span>`;
        break;
      case "ident": {
        // Treat schema.func( as a single function name
        let name = t.text;
        let j = i;
        if (tokens[j + 1]?.text === "." && tokens[j + 2]?.kind === "ident") {
          name = `${t.text}.${tokens[j + 2]?.text}`;
          j += 2;
        }
        if (tokens[j + 1]?.text === "(" && !KEYWORDS.has(t.text.toUpperCase())) {
          const href = linkFunction(name);
          const inner = escapeHtml(name);
          html += href ? `<a class="f" href="${escapeHtml(href)}">${inner}</a>` : `<span class="f">${inner}</span>`;
          i = j;
          break;
        }
        if (KEYWORDS.has(t.text.toUpperCase())) html += `<span class="k">${esc}</span>`;
        else if (tokens[i - 1]?.text === "::") html += `<span class="t">${esc}</span>`;
        else html += esc;
        break;
      }
      case "other":
        html += t.text === "::" ? `<span class="o">${esc}</span>` : esc;
        break;
      default:
        html += esc;
    }
  }
  return html;
}

/** Lists the functions called in an expression (schema-qualified when written that way). */
export function calledFunctions(sql: string): string[] {
  const tokens = tokenize(sql);
  if (!tokens) return [];
  const out = new Set<string>();
  for (let i = 0; i < tokens.length; i++) {
    const t = tokens[i] as Token;
    if (t.kind !== "ident" || KEYWORDS.has(t.text.toUpperCase())) continue;
    let name = t.text;
    let j = i;
    if (tokens[j + 1]?.text === "." && tokens[j + 2]?.kind === "ident") {
      name = `${t.text}.${tokens[j + 2]?.text}`;
      j += 2;
    }
    if (tokens[j + 1]?.text === "(") out.add(name);
    i = j;
  }
  return [...out];
}
