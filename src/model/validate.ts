import { loadRulesSchema, validate } from "./schema.ts";
import { FORMAT_VERSION, type RulesDocument } from "./types.ts";

export class RulesDocumentError extends Error {}

/**
 * Validates render input: a few hand-written checks with specific messages, then the whole document against the bundled schemas/rules.schema.json.
 */
export function assertRulesDocument(value: unknown): asserts value is RulesDocument {
  if (!value || typeof value !== "object") throw new RulesDocumentError("rules.json is not an object");
  const v = value as Record<string, unknown>;
  if (v.formatVersion !== FORMAT_VERSION) {
    throw new RulesDocumentError(`Unsupported formatVersion (supported: ${FORMAT_VERSION})`);
  }
  for (const key of ["roles", "tables", "views", "functions", "externalForeignKeys", "eventTriggers"]) {
    if (!Array.isArray(v[key])) throw new RulesDocumentError(`${key} is not an array`);
  }
  const source = v.source as Record<string, unknown> | undefined;
  if (!source || typeof source.schema !== "string") throw new RulesDocumentError("source.schema is missing");
  const excluded = v.excluded as Record<string, unknown> | undefined;
  if (!excluded || !Array.isArray(excluded.eventTriggers)) throw new RulesDocumentError("excluded is missing");
  for (const [i, t] of (v.tables as unknown[]).entries()) {
    const table = t as Record<string, unknown>;
    if (typeof table.name !== "string") throw new RulesDocumentError(`tables[${i}].name is missing`);
    for (const key of ["columns", "policies", "triggers", "constraints", "grants"]) {
      if (!Array.isArray(table[key])) throw new RulesDocumentError(`tables[${i}].${key} is not an array`);
    }
  }
  for (const [i, f] of (v.functions as unknown[]).entries()) {
    const fn = f as Record<string, unknown>;
    if (typeof fn.name !== "string") throw new RulesDocumentError(`functions[${i}].name is missing`);
    if (fn.comment !== undefined && fn.comment !== null && typeof fn.comment !== "string") {
      throw new RulesDocumentError(`functions[${i}].comment is not a string`);
    }
    if (fn.analysis !== undefined) assertAnalysis(fn.analysis, `functions[${i}].analysis`);
  }
  // The renderer reads nearly every field (rls, grants, triggers, views, analysis, ...), so the whole document is
  // checked against the bundled schema rather than a hand-picked subset
  const errors = validate(loadRulesSchema(), value);
  if (errors.length) {
    throw new RulesDocumentError(
      `rules.json does not match schemas/rules.schema.json: ${errors.slice(0, 5).join("; ")}`
    );
  }
}

const ANALYSIS_STATUSES = new Set(["analyzed", "partial", "failed", "unsupported"]);

function assertAnalysis(value: unknown, at: string): void {
  if (!value || typeof value !== "object") throw new RulesDocumentError(`${at} is not an object`);
  const a = value as Record<string, unknown>;
  if (!ANALYSIS_STATUSES.has(a.status as string)) throw new RulesDocumentError(`${at}.status is not a known status`);
  for (const key of [
    "guards",
    "earlyReturns",
    "sideEffects",
    "newColumns",
    "oldColumns",
    "changeCheckedColumns",
    "calledFunctions",
    "headerComments"
  ]) {
    if (!Array.isArray(a[key])) throw new RulesDocumentError(`${at}.${key} is not an array`);
  }
  if (a.reason !== null && typeof a.reason !== "string") throw new RulesDocumentError(`${at}.reason is not a string`);
  if (typeof a.dynamicSql !== "boolean") throw new RulesDocumentError(`${at}.dynamicSql is not a boolean`);
  if (!Number.isInteger(a.unparsedCount)) throw new RulesDocumentError(`${at}.unparsedCount is not an integer`);
  for (const key of ["newColumns", "oldColumns", "changeCheckedColumns", "calledFunctions", "headerComments"]) {
    assertStrings(a[key], `${at}.${key}`);
  }
  for (const [g, guard] of (a.guards as unknown[]).entries()) {
    const where = `${at}.guards[${g}]`;
    const o = asObject(guard, where);
    assertPath(o.path, `${where}.path`);
    assertString(o.statement, `${where}.statement`);
    for (const key of ["message", "arguments", "errcode", "detail", "hint"])
      assertNullableString(o[key], `${where}.${key}`);
  }
  for (const [r, ret] of (a.earlyReturns as unknown[]).entries()) {
    const o = asObject(ret, `${at}.earlyReturns[${r}]`);
    assertPath(o.path, `${at}.earlyReturns[${r}].path`);
    assertString(o.statement, `${at}.earlyReturns[${r}].statement`);
  }
  for (const [e, effect] of (a.sideEffects as unknown[]).entries()) {
    const o = asObject(effect, `${at}.sideEffects[${e}]`);
    assertString(o.operation, `${at}.sideEffects[${e}].operation`);
    assertNullableString(o.schema, `${at}.sideEffects[${e}].schema`);
    assertString(o.name, `${at}.sideEffects[${e}].name`);
  }
}

function asObject(value: unknown, at: string): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value))
    throw new RulesDocumentError(`${at} is not an object`);
  return value as Record<string, unknown>;
}

function assertString(value: unknown, at: string): void {
  if (typeof value !== "string") throw new RulesDocumentError(`${at} is not a string`);
}

function assertNullableString(value: unknown, at: string): void {
  if (value !== null) assertString(value, at);
}

function assertStrings(value: unknown, at: string): void {
  if (!Array.isArray(value) || !value.every((v) => typeof v === "string")) {
    throw new RulesDocumentError(`${at} is not an array of strings`);
  }
}

/** Each path element is an object whose kind is a string, sql a string or null, notTaken an array of strings. */
function assertPath(value: unknown, at: string): void {
  if (!Array.isArray(value)) throw new RulesDocumentError(`${at} is not an array`);
  for (const [p, element] of value.entries()) {
    const o = asObject(element, `${at}[${p}]`);
    assertString(o.kind, `${at}[${p}].kind`);
    assertNullableString(o.sql, `${at}[${p}].sql`);
    assertStrings(o.notTaken, `${at}[${p}].notTaken`);
    if (o.subject !== undefined) assertString(o.subject, `${at}[${p}].subject`);
    if (o.comment !== undefined) assertString(o.comment, `${at}[${p}].comment`);
  }
}
