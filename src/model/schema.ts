import { existsSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

/**
 * A deliberately small JSON Schema checker covering only the keywords used by schemas/rules.schema.json
 * (type, const, enum, required, additionalProperties: false, properties, items, oneOf, $ref, minimum).
 * It keeps the schema and the TypeScript types from drifting apart without adding a validator dependency.
 */
type Schema = Record<string, unknown>;

let cached: Schema | undefined;

/** The bundled schemas/rules.schema.json (at the package root whether running from src/ or dist/). */
export function loadRulesSchema(): Schema {
  if (cached) return cached;
  const here = dirname(fileURLToPath(import.meta.url));
  const candidates = [
    join(here, "..", "schemas", "rules.schema.json"),
    join(here, "..", "..", "schemas", "rules.schema.json")
  ];
  const path = candidates.find((c) => existsSync(c)) ?? (candidates[0] as string);
  cached = JSON.parse(readFileSync(path, "utf8")) as Schema;
  return cached;
}

export function validate(root: Schema, value: unknown): string[] {
  const errors: string[] = [];
  const typeOf = (v: unknown) =>
    v === null ? "null" : Array.isArray(v) ? "array" : Number.isInteger(v) ? "integer" : typeof v;
  const matchesType = (t: string, v: unknown) => typeOf(v) === t || (t === "number" && typeof v === "number");

  const walk = (schema: Schema, v: unknown, path: string): void => {
    if (typeof schema.$ref === "string") {
      const key = schema.$ref.replace("#/$defs/", "");
      walk((root.$defs as Record<string, Schema>)[key] as Schema, v, path);
      return;
    }
    if (Array.isArray(schema.oneOf)) {
      const passing = (schema.oneOf as Schema[]).filter((s) => {
        const before = errors.length;
        walk(s, v, path);
        const ok = errors.length === before;
        errors.length = before;
        return ok;
      });
      if (passing.length !== 1) errors.push(`${path}: matches ${passing.length} of oneOf`);
      return;
    }
    // Messages name the path and the expected shape only; values of the (untrusted) input are never echoed
    if ("const" in schema && v !== schema.const) errors.push(`${path}: unexpected value`);
    if (Array.isArray(schema.enum) && !schema.enum.includes(v)) errors.push(`${path}: not an allowed value`);
    if (schema.type !== undefined) {
      const types = Array.isArray(schema.type) ? (schema.type as string[]) : [schema.type as string];
      if (!types.some((t) => matchesType(t, v))) {
        errors.push(`${path}: expected ${types.join("|")}, got ${typeOf(v)}`);
        return;
      }
    }
    if (typeof schema.minimum === "number" && typeof v === "number" && v < schema.minimum)
      errors.push(`${path}: below minimum`);
    if (typeOf(v) === "object") {
      const obj = v as Record<string, unknown>;
      const props = (schema.properties ?? {}) as Record<string, Schema>;
      // Own properties only: `in` and plain indexing would also find Object.prototype members such as
      // constructor or __proto__, letting them slip past additionalProperties: false
      for (const key of (schema.required ?? []) as string[]) {
        if (!Object.hasOwn(obj, key)) errors.push(`${path}: missing ${key}`);
      }
      for (const [key, child] of Object.entries(obj)) {
        const childSchema = Object.hasOwn(props, key) ? props[key] : undefined;
        if (childSchema) walk(childSchema, child, `${path}.${key}`);
        else if (schema.additionalProperties === false) {
          // JSON.stringify escapes control characters, so a crafted key cannot inject terminal escapes into the log
          errors.push(`${path}: unexpected property ${JSON.stringify(key.slice(0, 64))}`);
        }
      }
    }
    if (Array.isArray(v) && schema.items) v.forEach((item, i) => walk(schema.items as Schema, item, `${path}[${i}]`));
  };
  walk(root, value, "$");
  return errors;
}
