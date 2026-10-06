/**
 * Deterministic, purpose-built analysis of PL/pgSQL function bodies: guards (IF ... RAISE EXCEPTION),
 * early returns, side effects, NEW/OLD column references, called functions and comments.
 * It is a summary for reading, not a PL/pgSQL parser: whatever it cannot follow is reported as unparsed
 * and the full definition stays the authoritative source.
 */
import type { FunctionAnalysis, FunctionInfo, Guard, GuardPathElement, EarlyReturn, SideEffect } from "./types.ts";

export class PlpgsqlSyntaxError extends Error {}

const MAX_COMMENT_LENGTH = 2000;

interface Masked {
  /** Comments replaced with spaces; string literals kept. Used to slice conditions and messages. */
  code: string;
  /** Comments and the contents of string literals / quoted identifiers replaced, same length as the input. */
  masked: string;
  comments: { start: number; end: number; text: string }[];
}

const isIdentChar = (c: string | undefined) => c !== undefined && /[A-Za-z0-9_$]/.test(c);

/**
 * Blanks comments and string contents while keeping every offset, so that keyword detection never fires
 * inside a comment, a literal or a dollar-quoted dynamic SQL string. Throws on unterminated constructs.
 */
export function maskBody(src: string): Masked {
  const code = src.split("");
  const masked = src.split("");
  const comments: Masked["comments"] = [];
  const blank = (from: number, to: number, both: boolean) => {
    for (let k = from; k < to; k++) {
      const keep = src[k] === "\n" ? "\n" : " ";
      masked[k] = keep;
      if (both) code[k] = keep;
    }
  };
  const fill = (from: number, to: number) => {
    for (let k = from; k < to; k++) masked[k] = src[k] === "\n" ? "\n" : "_";
  };
  let i = 0;
  while (i < src.length) {
    const c = src[i] as string;
    const next = src[i + 1];
    if (c === "-" && next === "-") {
      let j = src.indexOf("\n", i);
      if (j < 0) j = src.length;
      comments.push({ start: i, end: j, text: src.slice(i + 2, j) });
      blank(i, j, true);
      i = j;
    } else if (c === "/" && next === "*") {
      // PostgreSQL block comments nest
      let depth = 0;
      let j = i;
      for (;;) {
        if (j >= src.length) throw new PlpgsqlSyntaxError("unterminated block comment");
        if (src[j] === "/" && src[j + 1] === "*") {
          depth++;
          j += 2;
        } else if (src[j] === "*" && src[j + 1] === "/") {
          depth--;
          j += 2;
          if (depth === 0) break;
        } else j++;
      }
      comments.push({ start: i, end: j, text: src.slice(i + 2, j - 2) });
      blank(i, j, true);
      i = j;
    } else if (c === "'") {
      const escapes = (src[i - 1] === "E" || src[i - 1] === "e") && !isIdentChar(src[i - 2]);
      let j = i + 1;
      for (;;) {
        if (j >= src.length) throw new PlpgsqlSyntaxError("unterminated string literal");
        if (escapes && src[j] === "\\") j += 2;
        else if (src[j] === "'" && src[j + 1] === "'") j += 2;
        else if (src[j] === "'") break;
        else j++;
      }
      fill(i + 1, j);
      i = j + 1;
    } else if (c === '"') {
      let j = i + 1;
      for (;;) {
        if (j >= src.length) throw new PlpgsqlSyntaxError("unterminated quoted identifier");
        if (src[j] === '"' && src[j + 1] === '"') j += 2;
        else if (src[j] === '"') break;
        else j++;
      }
      fill(i + 1, j);
      i = j + 1;
    } else if (c === "$" && !isIdentChar(src[i - 1])) {
      // $tag$ ... $tag$; a tag never starts with a digit, which keeps $1 parameters out
      const m = /^\$([A-Za-z_][A-Za-z0-9_]*)?\$/.exec(src.slice(i, i + 64));
      if (!m) {
        i++;
        continue;
      }
      const tag = m[0];
      const close = src.indexOf(tag, i + tag.length);
      if (close < 0) throw new PlpgsqlSyntaxError("unterminated dollar-quoted string");
      // Render the whole dollar-quoted string as one masked literal: '____'
      masked[i] = "'";
      fill(i + 1, close + tag.length - 1);
      masked[close + tag.length - 1] = "'";
      i = close + tag.length;
    } else i++;
  }
  return { code: code.join(""), masked: masked.join(""), comments };
}

/** The body between `AS $tag$` and the last `$tag$` of a pg_get_functiondef result. */
export function extractBody(definition: string): string | null {
  const m = /\bAS\s+(\$[A-Za-z0-9_]*\$)/.exec(definition);
  if (!m) return null;
  const start = m.index + m[0].length;
  const end = definition.lastIndexOf(m[1] as string);
  if (end <= start) return null;
  return definition.slice(start, end);
}

interface Tok {
  text: string;
  upper: string;
  kind: "word" | "str" | "punct" | "op" | "num";
  start: number;
  end: number;
}

function tokenize(masked: string): Tok[] {
  const toks: Tok[] = [];
  const re =
    /\s+|([A-Za-z_][A-Za-z0-9_$]*)|('[^']*')|("[^"]*")|([0-9]+(?:\.[0-9]+)?)|([(),;[\].])|([^\sA-Za-z0-9_'"(),;[\].]+)/gy;
  let m: RegExpExecArray | null;
  while (re.lastIndex < masked.length && (m = re.exec(masked)) !== null) {
    const text = m[0];
    const start = m.index;
    if (m[1] !== undefined)
      toks.push({ text, upper: text.toUpperCase(), kind: "word", start, end: start + text.length });
    else if (m[2] !== undefined) toks.push({ text, upper: "", kind: "str", start, end: start + text.length });
    else if (m[3] !== undefined) toks.push({ text, upper: "", kind: "word", start, end: start + text.length });
    else if (m[4] !== undefined) toks.push({ text, upper: "", kind: "num", start, end: start + text.length });
    else if (m[5] !== undefined) toks.push({ text, upper: text, kind: "punct", start, end: start + text.length });
    else if (m[6] !== undefined) toks.push({ text, upper: text, kind: "op", start, end: start + text.length });
  }
  if (re.lastIndex < masked.length) throw new PlpgsqlSyntaxError("unexpected character");
  return toks;
}

/** The common escapes of E'' strings; any other backslash sequence yields the character itself. */
const BACKSLASH_ESCAPES: Record<string, string> = { n: "\n", t: "\t", r: "\r", b: "\b", f: "\f" };

const RAISE_LEVELS = new Set(["DEBUG", "LOG", "INFO", "NOTICE", "WARNING", "EXCEPTION"]);

class Walker {
  i = 0;
  guards: Guard[] = [];
  returns: EarlyReturn[] = [];
  constructor(
    private toks: Tok[],
    private m: Masked
  ) {}

  private peek(offset = 0): Tok | undefined {
    return this.toks[this.i + offset];
  }

  private expectWord(word: string): void {
    const t = this.peek();
    if (!t || t.upper !== word) throw new PlpgsqlSyntaxError(`expected ${word} near offset ${t?.start ?? "end"}`);
    this.i++;
  }

  private slice(from: number, to: number): string {
    const a = this.toks[from];
    const b = this.toks[to - 1];
    if (!a || !b || to <= from) return "";
    return collapse(this.m.code.slice(a.start, b.end), this.m.masked.slice(a.start, b.end));
  }

  /** Comment block directly preceding token index k (only whitespace and comments in between). */
  private commentBefore(k: number): string | undefined {
    const tok = this.toks[k];
    if (!tok) return undefined;
    const prevEnd = k > 0 ? (this.toks[k - 1]?.end ?? 0) : 0;
    const texts = this.m.comments
      .filter((c) => c.start >= prevEnd && c.end <= tok.start)
      .map((c) => c.text.trim())
      .filter(Boolean);
    return texts.length ? texts.join("\n").slice(0, MAX_COMMENT_LENGTH) : undefined;
  }

  /** Index of the next `word` (one of `stops`) at paren depth 0 and CASE depth 0, starting at the cursor. */
  private scanTo(stops: Set<string>, alsoSemicolon = false): number {
    let paren = 0;
    let caseDepth = 0;
    for (let k = this.i; k < this.toks.length; k++) {
      const t = this.toks[k] as Tok;
      if (t.text === "(" || t.text === "[") paren++;
      else if (t.text === ")" || t.text === "]") paren--;
      else if (paren === 0 && t.upper === "CASE") caseDepth++;
      else if (paren === 0 && caseDepth > 0 && t.upper === "END") caseDepth--;
      else if (paren === 0 && caseDepth === 0 && (stops.has(t.upper) || (alsoSemicolon && t.text === ";"))) return k;
    }
    throw new PlpgsqlSyntaxError(`missing ${[...stops].join("/")}`);
  }

  private skipStatement(): void {
    const k = this.scanTo(new Set(), true);
    this.i = k + 1;
  }

  /** [DECLARE ...] BEGIN statements [EXCEPTION handlers] END [label] [;] */
  block(path: GuardPathElement[]): void {
    if (this.peek()?.upper === "DECLARE") {
      // Declarations never contain BEGIN outside a string, so the first BEGIN closes the section
      while (this.peek() && this.peek()?.upper !== "BEGIN") this.i++;
    }
    this.expectWord("BEGIN");
    this.statements(new Set(["END", "EXCEPTION"]), path);
    if (this.peek()?.upper === "EXCEPTION") {
      this.i++;
      while (this.peek()?.upper === "WHEN") {
        const header = this.i;
        this.i++;
        const thenAt = this.scanTo(new Set(["THEN"]));
        const sql = this.slice(header + 1, thenAt);
        this.i = thenAt + 1;
        this.statements(new Set(["WHEN", "END"]), [...path, { kind: "EXCEPTION WHEN", sql, notTaken: [] }]);
      }
    }
    this.expectWord("END");
    this.skipEndLabel();
    if (this.peek()?.text === ";") this.i++;
  }

  /** `END label;` / `END LOOP label;`: a word is a label only when the statement ends right after it. */
  private skipEndLabel(): void {
    const next = this.peek(1);
    if (this.peek()?.kind === "word" && (next === undefined || next.text === ";")) this.i++;
  }

  statements(stops: Set<string>, path: GuardPathElement[]): void {
    for (;;) {
      const t = this.peek();
      if (!t) {
        if (stops.size === 0) return;
        throw new PlpgsqlSyntaxError("unexpected end of body");
      }
      if (stops.has(t.upper)) return;
      if (t.text === ";") {
        this.i++;
        continue;
      }
      if (t.text === "<<") {
        // <<label>>
        while (this.peek() && this.peek()?.text !== ">>") this.i++;
        this.i++;
        continue;
      }
      switch (t.upper) {
        case "IF":
          this.ifStatement(path);
          break;
        case "CASE":
          this.caseStatement(path);
          break;
        case "LOOP":
        case "WHILE":
        case "FOR":
        case "FOREACH":
          this.loop(path);
          break;
        case "DECLARE":
        case "BEGIN":
          this.block(path);
          break;
        case "RAISE":
          this.raise(path);
          break;
        case "RETURN":
          this.ret(path);
          break;
        default:
          this.skipStatement();
      }
    }
  }

  private ifStatement(path: GuardPathElement[]): void {
    const comment = this.commentBefore(this.i);
    const prior: string[] = [];
    let kind: GuardPathElement["kind"] = "IF";
    this.i++;
    for (;;) {
      const thenAt = this.scanTo(new Set(["THEN"]));
      const sql = this.slice(this.i, thenAt);
      this.i = thenAt + 1;
      this.statements(new Set(["ELSIF", "ELSEIF", "ELSE", "END"]), [
        ...path,
        { kind, sql, notTaken: [...prior], ...(comment && kind === "IF" ? { comment } : {}) }
      ]);
      prior.push(sql);
      const t = this.peek();
      if (t?.upper === "ELSIF" || t?.upper === "ELSEIF") {
        kind = "ELSIF";
        this.i++;
        continue;
      }
      if (t?.upper === "ELSE") {
        this.i++;
        this.statements(new Set(["END"]), [...path, { kind: "ELSE", sql: null, notTaken: [...prior] }]);
      }
      break;
    }
    this.expectWord("END");
    this.expectWord("IF");
    if (this.peek()?.text === ";") this.i++;
  }

  private caseStatement(path: GuardPathElement[]): void {
    this.i++;
    let subject: string | undefined;
    if (this.peek()?.upper !== "WHEN") {
      const whenAt = this.scanTo(new Set(["WHEN"]));
      subject = this.slice(this.i, whenAt);
      this.i = whenAt;
    }
    const prior: string[] = [];
    while (this.peek()?.upper === "WHEN") {
      this.i++;
      const thenAt = this.scanTo(new Set(["THEN"]));
      const sql = this.slice(this.i, thenAt);
      this.i = thenAt + 1;
      this.statements(new Set(["WHEN", "ELSE", "END"]), [
        ...path,
        { kind: "WHEN", sql, notTaken: [...prior], ...(subject ? { subject } : {}) }
      ]);
      prior.push(sql);
    }
    if (this.peek()?.upper === "ELSE") {
      this.i++;
      this.statements(new Set(["END"]), [
        ...path,
        { kind: "ELSE", sql: null, notTaken: [...prior], ...(subject ? { subject } : {}) }
      ]);
    }
    this.expectWord("END");
    this.expectWord("CASE");
    if (this.peek()?.text === ";") this.i++;
  }

  private loop(path: GuardPathElement[]): void {
    const header = this.i;
    const loopAt = this.peek()?.upper === "LOOP" ? this.i : this.scanTo(new Set(["LOOP"]));
    const sql = this.slice(header, loopAt);
    this.i = loopAt + 1;
    this.statements(new Set(["END"]), [...path, { kind: "LOOP", sql: sql || "LOOP", notTaken: [] }]);
    this.expectWord("END");
    this.expectWord("LOOP");
    this.skipEndLabel();
    if (this.peek()?.text === ";") this.i++;
  }

  private ret(path: GuardPathElement[]): void {
    const start = this.i;
    const end = this.scanTo(new Set(), true);
    this.i = end + 1;
    // RETURN NEXT / RETURN QUERY append to the result set and keep running, so they do not exit the function
    const second = this.toks[start + 1]?.upper;
    if (second === "NEXT" || second === "QUERY") return;
    if (path.length > 0) this.returns.push({ path, statement: this.slice(start, end) });
  }

  private raise(path: GuardPathElement[]): void {
    const start = this.i;
    const end = this.scanTo(new Set(), true);
    this.i = end + 1;
    let k = start + 1;
    const level = this.toks[k]?.upper ?? "";
    if (RAISE_LEVELS.has(level)) k++;
    // RAISE without a level raises an EXCEPTION
    if (RAISE_LEVELS.has(level) && level !== "EXCEPTION") return;
    const guard: Guard = {
      path,
      message: null,
      arguments: null,
      errcode: null,
      detail: null,
      hint: null,
      statement: this.slice(start, end)
    };
    let usingAt = end;
    for (let p = k, depth = 0; p < end; p++) {
      const t = this.toks[p] as Tok;
      if (t.text === "(") depth++;
      else if (t.text === ")") depth--;
      else if (depth === 0 && t.upper === "USING") {
        usingAt = p;
        break;
      }
    }
    let first = this.toks[k];
    // E'...' tokenizes as the word E followed by an adjacent string literal
    const escaped = first?.upper === "E" && this.toks[k + 1]?.kind === "str" && this.toks[k + 1]?.start === first.end;
    if (escaped) {
      k++;
      first = this.toks[k];
    }
    if (k >= end)
      guard.message = null; // bare RAISE; re-raises the current exception
    else if (escaped && first) {
      guard.message = this.literal(first, true);
      const comma = this.toks[k + 1]?.text === "," ? k + 2 : -1;
      if (comma > 0 && comma < usingAt) guard.arguments = this.slice(comma, usingAt);
    } else if (first?.kind === "str") {
      guard.message = this.literal(first);
      const comma = this.toks[k + 1]?.text === "," ? k + 2 : -1;
      if (comma > 0 && comma < usingAt) guard.arguments = this.slice(comma, usingAt);
    } else {
      // RAISE condition_name / RAISE SQLSTATE 'xxxxx'
      guard.errcode =
        first?.upper === "SQLSTATE" && this.toks[k + 1]?.kind === "str"
          ? this.literal(this.toks[k + 1] as Tok)
          : this.slice(k, usingAt);
    }
    if (usingAt < end) {
      for (const [name, value] of this.usingOptions(usingAt + 1, end)) {
        if (name === "ERRCODE") guard.errcode = value;
        else if (name === "MESSAGE") guard.message = value;
        else if (name === "DETAIL") guard.detail = value;
        else if (name === "HINT") guard.hint = value;
      }
    }
    this.guards.push(guard);
  }

  private usingOptions(from: number, to: number): [string, string][] {
    const out: [string, string][] = [];
    let k = from;
    while (k < to) {
      const name = this.toks[k]?.upper ?? "";
      if (this.toks[k + 1]?.text !== "=" && this.toks[k + 1]?.text !== ":=") break;
      let e = k + 2;
      for (let depth = 0; e < to; e++) {
        const t = this.toks[e] as Tok;
        if (t.text === "(") depth++;
        else if (t.text === ")") depth--;
        else if (depth === 0 && t.text === ",") break;
      }
      const valueToks = this.toks.slice(k + 2, e);
      out.push([
        name,
        valueToks.length === 1 && valueToks[0]?.kind === "str" ? this.literal(valueToks[0]) : this.slice(k + 2, e)
      ]);
      k = e + 1;
    }
    return out;
  }

  /** Decodes a string literal token from the original text ('' → ', dollar quotes and E'' prefixes removed). */
  private literal(t: Tok, escapes = false): string {
    const raw = this.m.code.slice(t.start, t.end);
    if (raw.startsWith("$")) {
      const tag = /^\$[A-Za-z0-9_]*\$/.exec(raw)?.[0] ?? "$$";
      return raw.slice(tag.length, raw.length - tag.length);
    }
    const inner = raw.slice(1, -1);
    if (!escapes) return inner.replace(/''/g, "'");
    return inner.replace(/''|\\([\s\S])/g, (_match, ch: string | undefined) =>
      ch === undefined ? "'" : (BACKSLASH_ESCAPES[ch] ?? ch)
    );
  }
}

/** Collapses whitespace runs outside string literals (where the masked text is also whitespace). */
function collapse(code: string, masked: string): string {
  let out = "";
  let ws = false;
  for (let k = 0; k < code.length; k++) {
    const isWs = /\s/.test(masked[k] as string) && /\s/.test(code[k] as string);
    if (isWs) {
      ws = true;
      continue;
    }
    if (ws && out) out += " ";
    ws = false;
    out += code[k];
  }
  return out;
}

const IDENT = String.raw`(?:[A-Za-z_][A-Za-z0-9_$]*|"_*")`;

/** Reads `ident[.ident]` at a position of the masked text, returning names from the original text. */
function readName(
  src: string,
  masked: string,
  at: number
): { schema: string | null; name: string; end: number } | null {
  const re = new RegExp(String.raw`\s*(?:ONLY\s+)?(${IDENT})(?:\s*\.\s*(${IDENT}))?`, "iy");
  re.lastIndex = at;
  const m = re.exec(masked);
  if (!m || !m[1]) return null;
  const pos1 = masked.indexOf(m[1], at);
  const n1 = normalizeIdent(src.slice(pos1, pos1 + m[1].length));
  if (m[2]) {
    const pos2 = masked.indexOf(m[2], pos1 + m[1].length);
    return { schema: n1, name: normalizeIdent(src.slice(pos2, pos2 + m[2].length)), end: re.lastIndex };
  }
  return { schema: null, name: n1, end: re.lastIndex };
}

function normalizeIdent(s: string): string {
  return s.startsWith('"') ? s.slice(1, -1).replace(/""/g, '"') : s.toLowerCase();
}

function sideEffects(src: string, masked: string): SideEffect[] {
  const out = new Map<string, SideEffect>();
  const add = (operation: SideEffect["operation"], n: { schema: string | null; name: string } | null) => {
    if (!n || /^(SET|SELECT|VALUES)$/i.test(n.name)) return;
    out.set(`${operation}|${n.schema}|${n.name}`, { operation, schema: n.schema, name: n.name });
  };
  const scan = (re: RegExp, fn: (m: RegExpExecArray) => void) => {
    for (const m of masked.matchAll(re)) fn(m as RegExpExecArray);
  };
  scan(/\bINSERT\s+INTO\b/gi, (m) => add("INSERT", readName(src, masked, m.index + m[0].length)));
  scan(/\bMERGE\s+INTO\b/gi, (m) => add("MERGE", readName(src, masked, m.index + m[0].length)));
  scan(/\bDELETE\s+FROM\b/gi, (m) => add("DELETE", readName(src, masked, m.index + m[0].length)));
  scan(/\bUPDATE\b/gi, (m) => {
    // FOR [NO KEY] UPDATE, ON CONFLICT ... DO UPDATE, BEFORE/AFTER UPDATE, ON UPDATE are not writes to a table
    const before = /([A-Za-z_]+)\s*$/.exec(masked.slice(Math.max(0, m.index - 40), m.index))?.[1]?.toUpperCase();
    if (before && ["FOR", "DO", "KEY", "ON", "BEFORE", "AFTER", "OR", "OF"].includes(before)) return;
    const n = readName(src, masked, m.index + m[0].length);
    if (!n) return;
    // UPDATE <table> [[AS] alias] SET
    if (!/^\s*(?:(?:AS\s+)?[A-Za-z_][A-Za-z0-9_]*\s+)?SET\b/i.test(masked.slice(n.end, n.end + 80))) return;
    add("UPDATE", n);
  });
  scan(/\bTRUNCATE\b(?:\s+TABLE\b)?/gi, (m) => {
    const before = /([A-Za-z_]+)\s*$/.exec(masked.slice(Math.max(0, m.index - 40), m.index))?.[1]?.toUpperCase();
    if (before && ["ON", "BEFORE", "AFTER", "OR"].includes(before)) return;
    add("TRUNCATE", readName(src, masked, m.index + m[0].length));
  });
  scan(/\bPERFORM\b/gi, (m) => {
    const n = readName(src, masked, m.index + m[0].length);
    if (n && /^\s*\(/.test(masked.slice(n.end, n.end + 5))) add("PERFORM", n);
  });
  return [...out.values()];
}

function columnRefs(
  src: string,
  masked: string
): { newColumns: string[]; oldColumns: string[]; changeChecked: string[] } {
  const news = new Set<string>();
  const olds = new Set<string>();
  const changed = new Set<string>();
  const ref = String.raw`\b(NEW|OLD)\s*\.\s*(${IDENT})`;
  const colAt = (m: RegExpExecArray, group: number) => {
    const text = m[group] as string;
    const pos = m.index + m[0].lastIndexOf(text);
    return normalizeIdent(src.slice(pos, pos + text.length));
  };
  for (const m of masked.matchAll(new RegExp(ref, "gi"))) {
    const col = colAt(m as RegExpExecArray, 2);
    if ((m[1] as string).toUpperCase() === "NEW") news.add(col);
    else olds.add(col);
  }
  const cmp = new RegExp(
    // Each optional piece owns the whitespace after it: adjacent \s* quantifiers backtrack quadratically on long runs
    String.raw`\b(NEW|OLD)\s*\.\s*(${IDENT})\s*(?:\)\s*)?(?:::\s*[A-Za-z_][\w.]*(?:\[\])?\s*)?(?:IS\s+DISTINCT\s+FROM|<>|!=)\s*(?:\(\s*)?(NEW|OLD)\s*\.\s*(${IDENT})`,
    "gi"
  );
  for (const m of masked.matchAll(cmp)) {
    if ((m[1] as string).toUpperCase() === (m[3] as string).toUpperCase()) continue;
    const whole = m[0];
    const left = m[2] as string;
    const right = m[4] as string;
    const lp = m.index + whole.indexOf(left);
    const rp = m.index + whole.lastIndexOf(right);
    changed.add(normalizeIdent(src.slice(lp, lp + left.length)));
    changed.add(normalizeIdent(src.slice(rp, rp + right.length)));
  }
  return { newColumns: [...news].sort(), oldColumns: [...olds].sort(), changeChecked: [...changed].sort() };
}

/** Calls of functions known to exist in the target schema, written either bare or schema-qualified. */
function calledFunctions(masked: string, schema: string, known: ReadonlySet<string>, self: string): string[] {
  const out = new Set<string>();
  const re = new RegExp(String.raw`(?<![\w$.])(?:(${IDENT})\s*\.\s*)?([A-Za-z_][A-Za-z0-9_$]*)\s*\(`, "g");
  for (const m of masked.matchAll(re)) {
    const qualifier = m[1] ? normalizeIdent(m[1]) : null;
    if (qualifier !== null && qualifier !== schema) continue;
    const name = (m[2] as string).toLowerCase();
    if (known.has(name) && name !== self) out.add(name);
  }
  return [...out].sort();
}

/**
 * Functions of the target schema called from a policy expression (bare names). Calls qualified with another schema
 * (auth.uid(), extensions) and built-ins are not in `known`, so they are left out. Never throws: an expression that
 * cannot be masked yields no calls, and the expression itself is still shown as SQL.
 */
export function functionsCalledInExpression(sql: string, schema: string, known: ReadonlySet<string>): string[] {
  try {
    return calledFunctions(maskBody(sql).masked, schema, known, "");
  } catch {
    return [];
  }
}

function headerComments(m: Masked, toks: Tok[]): string[] {
  const begin = toks.findIndex((t) => t.upper === "BEGIN");
  const firstStatement = begin >= 0 ? toks[begin + 1] : toks[0];
  const limit = firstStatement?.start ?? m.code.length;
  return m.comments
    .filter((c) => c.start < limit)
    .map((c) => c.text.trim())
    .filter(Boolean)
    .map((c) => c.slice(0, MAX_COMMENT_LENGTH));
}

function emptyAnalysis(status: FunctionAnalysis["status"], reason: string | null): FunctionAnalysis {
  return {
    status,
    reason,
    guards: [],
    earlyReturns: [],
    sideEffects: [],
    newColumns: [],
    oldColumns: [],
    changeCheckedColumns: [],
    calledFunctions: [],
    headerComments: [],
    dynamicSql: false,
    unparsedCount: 0
  };
}

/**
 * Analyzes one function. Never throws: anything unexpected becomes status "failed" with a reason,
 * so one odd function cannot break the whole page.
 */
export function analyzeFunction(
  fn: Pick<FunctionInfo, "name" | "language" | "definition">,
  schema: string,
  knownFunctions: ReadonlySet<string>
): FunctionAnalysis {
  try {
    const isPlpgsql = fn.language === "plpgsql";
    if (!isPlpgsql && fn.language !== "sql")
      return emptyAnalysis("unsupported", `language ${fn.language} is not analyzed`);
    const body = fn.definition ? extractBody(fn.definition) : null;
    if (body === null) return emptyAnalysis("unsupported", "no function body found");
    const m = maskBody(body);
    const toks = tokenize(m.masked);
    // A SQL function has no control flow to follow, but its writes, calls and comments are still read
    const result = isPlpgsql
      ? emptyAnalysis("analyzed", null)
      : emptyAnalysis("unsupported", "language sql: no control flow to analyze; the body is the rule");
    result.sideEffects = sideEffects(body, m.masked);
    const cols = columnRefs(body, m.masked);
    result.newColumns = cols.newColumns;
    result.oldColumns = cols.oldColumns;
    result.changeCheckedColumns = cols.changeChecked;
    result.calledFunctions = calledFunctions(m.masked, schema, knownFunctions, fn.name);
    result.headerComments = headerComments(m, toks);
    result.dynamicSql = /\bEXECUTE\b/i.test(m.masked);
    if (!isPlpgsql) return result;
    const raiseCount = [...m.masked.matchAll(/\bRAISE\b(?!\s+(?:DEBUG|LOG|INFO|NOTICE|WARNING)\b)/gi)].length;
    const walker = new Walker(toks, m);
    try {
      walker.block([]);
      if (walker.i < toks.length && toks.slice(walker.i).some((t) => t.text !== ";")) {
        throw new PlpgsqlSyntaxError("unexpected text after the top-level END");
      }
    } catch (e) {
      result.status = "failed";
      result.reason = e instanceof Error ? e.message : String(e);
      result.unparsedCount = Math.max(raiseCount, 1);
      return result;
    }
    result.guards = walker.guards;
    result.earlyReturns = walker.returns;
    // A comment right above the first IF is already shown on that guard
    const attached = new Set(
      [...walker.guards, ...walker.returns].flatMap((g) => g.path.map((p) => p.comment)).filter(Boolean)
    );
    result.headerComments = result.headerComments.filter((c) => ![...attached].some((t) => t?.includes(c)));
    result.unparsedCount = Math.max(0, raiseCount - walker.guards.length);
    if (result.unparsedCount > 0) {
      result.status = "partial";
      result.reason = `${result.unparsedCount} RAISE statement(s) could not be placed in the control flow`;
    }
    return result;
  } catch (e) {
    const failed = emptyAnalysis("failed", e instanceof Error ? e.message : String(e));
    failed.unparsedCount = 1;
    return failed;
  }
}

export interface HelperRules {
  /** Function whose analysis this is (the trigger function itself at depth 0). */
  name: string;
  depth: number;
  /** Call path from the trigger function, excluding the function itself. */
  via: string[];
  analysis: FunctionAnalysis;
}

export interface CallTree {
  entries: HelperRules[];
  /** Calls not followed: depth limit reached or already visited on this traversal. */
  /** cycle: the callee is already on the call path; visited: already shown through another path; depth: limit. */
  truncated: { from: string; to: string; reason: "depth" | "cycle" | "visited" }[];
}

/**
 * Safety valve only: the call graph is followed until every reachable function is visited (each at most once),
 * and this bound just stops a pathological chain. Hitting it is reported as truncated.
 */
export const MAX_CALL_DEPTH = 8;

/** Walks the functions called (transitively) by a function, breadth first, visiting each function at most once. */
export function collectCallTree(
  root: string,
  analysisOf: (name: string) => FunctionAnalysis | undefined,
  maxDepth = MAX_CALL_DEPTH
): CallTree {
  const tree: CallTree = { entries: [], truncated: [] };
  const rootAnalysis = analysisOf(root);
  if (!rootAnalysis) return tree;
  const visited = new Set<string>([root]);
  let frontier: HelperRules[] = [{ name: root, depth: 0, via: [], analysis: rootAnalysis }];
  tree.entries.push(frontier[0] as HelperRules);
  while (frontier.length) {
    const next: HelperRules[] = [];
    for (const entry of frontier) {
      for (const callee of entry.analysis.calledFunctions) {
        if (callee === root || entry.via.includes(callee)) {
          tree.truncated.push({ from: entry.name, to: callee, reason: "cycle" });
          continue;
        }
        if (visited.has(callee)) {
          tree.truncated.push({ from: entry.name, to: callee, reason: "visited" });
          continue;
        }
        if (entry.depth >= maxDepth) {
          tree.truncated.push({ from: entry.name, to: callee, reason: "depth" });
          continue;
        }
        const analysis = analysisOf(callee);
        if (!analysis) continue;
        visited.add(callee);
        const child = { name: callee, depth: entry.depth + 1, via: [...entry.via, callee], analysis };
        tree.entries.push(child);
        next.push(child);
      }
    }
    frontier = next;
  }
  return tree;
}
