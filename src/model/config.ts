import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

export interface TagDefinition {
  id: string;
  label: string;
  pattern: string;
  flags?: string;
  description?: string;
}

export interface ViewerConfig {
  tags: TagDefinition[];
}

export interface CompiledTag {
  id: string;
  label: string;
  description: string;
  regex: RegExp;
}

export class ConfigError extends Error {}

export const CONFIG_FILE_NAME = "rls-access-viewer.config.json";

/** Path of the bundled default config (located at the package root whether running from src/ or dist/). */
export function defaultConfigPath(): string {
  const here = dirname(fileURLToPath(import.meta.url));
  const candidates = [join(here, "..", CONFIG_FILE_NAME), join(here, "..", "..", CONFIG_FILE_NAME)];
  for (const c of candidates) {
    try {
      readFileSync(c);
      return c;
    } catch {
      // try the next candidate
    }
  }
  return candidates[0] as string;
}

export function parseConfig(json: unknown): ViewerConfig {
  if (!json || typeof json !== "object" || !Array.isArray((json as { tags?: unknown }).tags)) {
    throw new ConfigError("The config file must contain a tags array");
  }
  const tags: TagDefinition[] = [];
  for (const [i, t] of (json as { tags: unknown[] }).tags.entries()) {
    const tag = t as Partial<TagDefinition>;
    if (typeof tag.id !== "string" || typeof tag.label !== "string" || typeof tag.pattern !== "string") {
      throw new ConfigError(`tags[${i}] requires string id, label and pattern`);
    }
    if (tag.flags !== undefined && !/^[imsu]*$/.test(tag.flags)) {
      throw new ConfigError(`tags[${i}].flags may only contain i, m, s or u`);
    }
    if (tag.description !== undefined && typeof tag.description !== "string") {
      throw new ConfigError(`tags[${i}].description must be a string`);
    }
    tags.push({ id: tag.id, label: tag.label, pattern: tag.pattern, flags: tag.flags, description: tag.description });
  }
  return { tags };
}

export function loadConfig(path?: string): ViewerConfig {
  const p = path ?? defaultConfigPath();
  let text: string;
  try {
    text = readFileSync(p, "utf8");
  } catch {
    throw new ConfigError(`Cannot read the config file: ${p}`);
  }
  try {
    return parseConfig(JSON.parse(text));
  } catch (e) {
    if (e instanceof ConfigError) throw e;
    throw new ConfigError(`The config file is not valid JSON: ${p}`);
  }
}

export function compileTags(config: ViewerConfig): CompiledTag[] {
  return config.tags.map((t, i) => {
    try {
      // No g flag: a global RegExp keeps lastIndex state between test() calls
      return {
        id: t.id,
        label: t.label,
        description: t.description ?? "",
        // Patterns come from the user's own config file, which is trusted input; invalid expressions are
        // rejected as a ConfigError.
        // bearer:disable javascript_lang_dynamic_regex
        regex: new RegExp(t.pattern, t.flags ?? "")
      };
    } catch {
      throw new ConfigError(`tags[${i}].pattern is not a valid regular expression`);
    }
  });
}

export function matchTags(sql: string, tags: CompiledTag[]): CompiledTag[] {
  return tags.filter((t) => t.regex.test(sql));
}
