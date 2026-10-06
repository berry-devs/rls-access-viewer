import pg from "pg";
import { analyzeFunction } from "../model/plpgsql.ts";
import { redactDeep } from "../model/redact.ts";
import {
  FORMAT_VERSION,
  type ColumnInfo,
  type Constraint,
  type ExternalForeignKey,
  type FkAction,
  type FunctionInfo,
  type Grant,
  type Policy,
  type PolicyCommand,
  type RulesDocument,
  type StorageRules,
  type TableRules,
  type Trigger,
  type TriggerEvent,
  type ViewRules
} from "../model/types.ts";
import { ConnectionConfigError } from "./connection.ts";
import * as Q from "./queries.ts";

export { ConnectionConfigError, resolveDbUrl, pickDbUrlFromStatusEnv, isLoopbackHost } from "./connection.ts";

export class DbConnectionError extends Error {}

export interface ExtractOptions {
  connectionString: string;
  schema?: string;
  now?: Date;
}

type Row = Record<string, unknown>;

/**
 * Queries the system catalogs in a READ ONLY transaction and returns the rules.json document.
 * The result is already redacted.
 */
export async function extractRules(options: ExtractOptions): Promise<RulesDocument> {
  const schema = options.schema ?? "public";
  let client: pg.Client;
  try {
    client = new pg.Client({
      connectionString: options.connectionString,
      connectionTimeoutMillis: 10_000,
      application_name: "rls-access-viewer"
    });
  } catch (e) {
    // pg parses the URL (and reads sslrootcert etc.) while constructing; its fs errors already start with the code,
    // so describePgError would print it twice
    throw new ConnectionConfigError(`Invalid connection settings: ${e instanceof Error ? e.message : String(e)}`);
  }
  // pg emits connection loss as an 'error' event; without a listener it would crash the process
  client.on("error", () => {});
  try {
    await client.connect();
  } catch (e) {
    // pg leaves the socket open when it fails during startup (e.g. an ErrorResponse the server does not follow with a
    // close), which would keep the process alive. Not awaited: end() resolves only once the server closes the socket
    client.end().catch(() => {});
    throw new DbConnectionError(`Could not connect to the database: ${describePgError(e)}`);
  }
  try {
    await client.query("BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY");
    await client.query("SET LOCAL statement_timeout = '120s'");
    // pg_get_expr qualifies names relative to search_path; putting the target schema first keeps output unqualified and readable
    await client.query("SELECT set_config('search_path', quote_ident($1) || ', pg_catalog', true)", [schema]);
    const exists = await client.query("SELECT 1 FROM pg_namespace WHERE nspname = $1", [schema]);
    if (exists.rowCount === 0) throw new DbConnectionError(`Schema ${schema} does not exist`);

    const q = async (sql: string, params: unknown[] = [schema]): Promise<Row[]> =>
      (await client.query(sql, params)).rows as Row[];

    const [version] = await q(Q.SQL_SERVER_VERSION, []);
    const roles = await q(Q.SQL_ROLES);
    const tables = await q(Q.SQL_TABLES);
    const columns = await q(Q.SQL_COLUMNS);
    const policies = await q(Q.SQL_POLICIES);
    const triggers = await q(Q.SQL_TRIGGERS);
    const constraints = await q(Q.SQL_CONSTRAINTS);
    const tableGrants = await q(Q.SQL_TABLE_GRANTS);
    const columnGrants = await q(Q.SQL_COLUMN_GRANTS);
    const views = await q(Q.SQL_VIEWS);
    const functions = await q(Q.SQL_FUNCTIONS);
    const [extFns] = await q(Q.SQL_EXTENSION_OWNED_FUNCTIONS);
    const [extRels] = await q(Q.SQL_EXTENSION_OWNED_RELATIONS);
    const eventTriggers = await q(Q.SQL_EVENT_TRIGGERS, []);
    const storage = await extractStorage(q);
    await client.query("ROLLBACK");

    const doc = assembleDocument({
      schema,
      serverVersion: String(version?.version ?? ""),
      now: options.now ?? new Date(),
      roles,
      tables,
      columns,
      policies,
      triggers,
      constraints,
      tableGrants,
      columnGrants,
      views,
      functions,
      extensionOwnedFunctions: Number(extFns?.count ?? 0),
      extensionOwnedRelations: Number(extRels?.count ?? 0),
      eventTriggers,
      ...(storage ? { storage } : {})
    });
    return redactDeep(doc);
  } catch (e) {
    if (e instanceof DbConnectionError) throw e;
    throw new DbConnectionError(`Catalog query failed: ${describePgError(e)}`);
  } finally {
    await client.end().catch(() => {});
  }
}

/**
 * Reads storage.objects from the catalogs and the settings columns of storage.buckets, the only table rows read:
 * they are configuration, not user data. storage.objects rows are never read.
 */
export async function extractStorage(
  q: (sql: string, params?: unknown[]) => Promise<Row[]>
): Promise<RawStorageCatalog | null> {
  const params = [STORAGE_SCHEMA];
  const exists = await q("SELECT 1 FROM pg_namespace WHERE nspname = $1", params);
  if (!exists.length) return null;
  const onlyObjects = (rows: Row[]) => rows.filter((r) => str(r.table_name) === "objects");
  const constraints = (await q(Q.SQL_CONSTRAINTS, params)).filter(
    (r) => str(r.table_schema) === STORAGE_SCHEMA && str(r.table_name) === "objects"
  );
  // A least-privilege role (CONNECT only) can read the catalogs but not storage.buckets; extraction goes on without
  // the settings instead of failing
  const columnRows = await q(Q.SQL_STORAGE_BUCKET_COLUMNS, []);
  const [accessRow] = await q(Q.SQL_STORAGE_BUCKET_ACCESS, []);
  const access = bucketsAccess(columnRows, accessRow);
  const existing = new Set(columnRows.map((r) => str(r.name)));
  const buckets = access.readable ? await q(Q.storageBucketsQuery(existing), []) : [];
  return {
    tables: (await q(Q.SQL_TABLES, params)).filter((r) => str(r.name) === "objects"),
    columns: onlyObjects(await q(Q.SQL_COLUMNS, params)),
    policies: onlyObjects(await q(Q.SQL_POLICIES, params)),
    triggers: onlyObjects(await q(Q.SQL_TRIGGERS, params)),
    constraints,
    tableGrants: onlyObjects(await q(Q.SQL_TABLE_GRANTS, params)),
    columnGrants: onlyObjects(await q(Q.SQL_COLUMN_GRANTS, params)),
    roles: await q(Q.SQL_ROLES, params),
    buckets,
    bucketsReadable: access.readable,
    bucketsFiltered: access.filtered
  };
}

/**
 * Decides whether the bucket settings can be read and whether row security may hide some buckets.
 * Column privileges are not enough: with row security active and no PERMISSIVE SELECT policy for the role,
 * storage.buckets returns no rows, which would otherwise look like "no buckets".
 */
export function bucketsAccess(columnRows: Row[], accessRow: Row | undefined): { readable: boolean; filtered: boolean } {
  const readableColumns = new Set(columnRows.filter((r) => Boolean(r.readable)).map((r) => str(r.name)));
  const existing = new Set(columnRows.map((r) => str(r.name)));
  const columnsReadable =
    existing.has("id") && Q.STORAGE_BUCKET_SETTINGS.every((c) => !existing.has(c) || readableColumns.has(c));
  const rlsActive = Boolean(accessRow?.rls_active);
  if (!columnsReadable || (rlsActive && !accessRow?.has_select_policy)) return { readable: false, filtered: false };
  return { readable: true, filtered: rlsActive };
}

/** Summarizes a pg error using only its code and message (never the connection parameters). */
function describePgError(e: unknown): string {
  if (e && typeof e === "object") {
    const err = e as { code?: unknown; message?: unknown };
    const code = typeof err.code === "string" ? err.code : "";
    const message = typeof err.message === "string" ? err.message : String(e);
    return code ? `${code} ${message}` : message;
  }
  return String(e);
}

export interface RawCatalog {
  schema: string;
  serverVersion: string;
  now: Date;
  roles: Row[];
  tables: Row[];
  columns: Row[];
  policies: Row[];
  triggers: Row[];
  constraints: Row[];
  tableGrants: Row[];
  columnGrants: Row[];
  views: Row[];
  functions: Row[];
  extensionOwnedFunctions: number;
  extensionOwnedRelations: number;
  eventTriggers: Row[];
  /** Absent when the storage schema does not exist. */
  storage?: RawStorageCatalog;
}

/** Catalog rows of storage.objects (already filtered to that table) plus the storage.buckets settings. */
export interface RawStorageCatalog {
  tables: Row[];
  columns: Row[];
  policies: Row[];
  triggers: Row[];
  constraints: Row[];
  tableGrants: Row[];
  columnGrants: Row[];
  roles: Row[];
  buckets: Row[];
  /** False when storage.buckets does not exist or the role may not read its settings (privileges or row security). */
  bucketsReadable: boolean;
  /** Row security applies to the role through its policies, so some buckets may be hidden. */
  bucketsFiltered: boolean;
}

export const STORAGE_SCHEMA = "storage";

const POLICY_COMMANDS: Record<string, PolicyCommand> = {
  r: "SELECT",
  a: "INSERT",
  w: "UPDATE",
  d: "DELETE",
  "*": "ALL"
};

const FK_ACTIONS: Record<string, FkAction> = {
  a: "NO ACTION",
  r: "RESTRICT",
  c: "CASCADE",
  n: "SET NULL",
  d: "SET DEFAULT"
};

// pg_trigger.tgtype bits (src/include/catalog/pg_trigger.h)
const TRIGGER_TYPE_ROW = 1 << 0;
const TRIGGER_TYPE_BEFORE = 1 << 1;
const TRIGGER_TYPE_INSERT = 1 << 2;
const TRIGGER_TYPE_DELETE = 1 << 3;
const TRIGGER_TYPE_UPDATE = 1 << 4;
const TRIGGER_TYPE_TRUNCATE = 1 << 5;
const TRIGGER_TYPE_INSTEAD = 1 << 6;

export function decodeTriggerType(tgtype: number): Pick<Trigger, "timing" | "level" | "events"> {
  const events: TriggerEvent[] = [];
  if (tgtype & TRIGGER_TYPE_INSERT) events.push("INSERT");
  if (tgtype & TRIGGER_TYPE_UPDATE) events.push("UPDATE");
  if (tgtype & TRIGGER_TYPE_DELETE) events.push("DELETE");
  if (tgtype & TRIGGER_TYPE_TRUNCATE) events.push("TRUNCATE");
  const timing = tgtype & TRIGGER_TYPE_INSTEAD ? "INSTEAD OF" : tgtype & TRIGGER_TYPE_BEFORE ? "BEFORE" : "AFTER";
  return { timing, level: tgtype & TRIGGER_TYPE_ROW ? "ROW" : "STATEMENT", events };
}

/** Extracts the WHEN (...) condition from pg_get_triggerdef output by matching parentheses. */
export function extractTriggerWhen(definition: string): string | null {
  const idx = definition.search(/\sWHEN \(/);
  if (idx < 0) return null;
  const start = definition.indexOf("(", idx);
  let depth = 0;
  let inString = false;
  for (let i = start; i < definition.length; i++) {
    const ch = definition[i];
    if (inString) {
      if (ch === "'") {
        if (definition[i + 1] === "'") i++;
        else inString = false;
      }
      continue;
    }
    if (ch === "'") inString = true;
    else if (ch === "(") depth++;
    else if (ch === ")") {
      depth--;
      if (depth === 0) return definition.slice(start + 1, i);
    }
  }
  return null;
}

const str = (v: unknown): string => (v === null || v === undefined ? "" : String(v));
const strOrNull = (v: unknown): string | null => (v === null || v === undefined ? null : String(v));
const strArray = (v: unknown): string[] => (Array.isArray(v) ? v.map(String) : []);

type TableCatalog = Pick<
  RawCatalog,
  "schema" | "columns" | "policies" | "triggers" | "constraints" | "tableGrants" | "columnGrants"
> & { tables: Row[] };

/** Builds the tables of one schema; also used for storage.objects so that both follow the same rules. */
function assembleTables(raw: TableCatalog): {
  tables: TableRules[];
  externalForeignKeys: ExternalForeignKey[];
  grantsByRelation: Map<string, Grant[]>;
} {
  const byTable = <T>(rows: Row[], map: (r: Row) => T): Map<string, T[]> => {
    const m = new Map<string, T[]>();
    for (const r of rows) {
      const key = str(r.table_name);
      const list = m.get(key) ?? [];
      list.push(map(r));
      m.set(key, list);
    }
    return m;
  };

  const columnsByTable = byTable<ColumnInfo>(raw.columns, (r) => ({
    name: str(r.name),
    type: str(r.type),
    notNull: Boolean(r.not_null),
    default: strOrNull(r.default_expr),
    identity: r.identity === "a" ? "ALWAYS" : r.identity === "d" ? "BY DEFAULT" : null,
    generated: str(r.generated) !== ""
  }));

  const policiesByTable = byTable<Policy>(raw.policies, (r) => ({
    name: str(r.name),
    command: POLICY_COMMANDS[str(r.cmd)] ?? "ALL",
    permissive: Boolean(r.permissive),
    roles: strArray(r.roles),
    using: strOrNull(r.using_expr),
    withCheck: strOrNull(r.with_check_expr)
  }));

  const triggersByTable = byTable<Trigger>(raw.triggers, (r) => {
    const definition = str(r.definition);
    const enabled = str(r.enabled);
    return {
      name: str(r.name),
      ...decodeTriggerType(Number(r.tgtype)),
      updateColumns: strArray(r.update_columns),
      when: extractTriggerWhen(definition),
      function: {
        schema: str(r.function_schema),
        name: str(r.function_name),
        securityDefiner: Boolean(r.function_secdef)
      },
      enabled: enabled === "D" || enabled === "R" || enabled === "A" ? enabled : "O",
      isConstraintTrigger: Boolean(r.is_constraint),
      definition
    };
  });

  const constraintsByTable = new Map<string, Constraint[]>();
  const externalForeignKeys: ExternalForeignKey[] = [];
  for (const r of raw.constraints) {
    const base = { name: str(r.name), columns: strArray(r.columns), definition: str(r.definition) };
    let c: Constraint;
    switch (str(r.contype)) {
      case "p":
        c = { kind: "primary", ...base };
        break;
      case "u":
        c = { kind: "unique", ...base };
        break;
      case "x":
        c = { kind: "exclusion", ...base };
        break;
      case "c":
        c = { kind: "check", ...base };
        break;
      default:
        c = {
          kind: "foreign",
          ...base,
          references: { schema: str(r.ref_schema), table: str(r.ref_table), columns: strArray(r.ref_columns) },
          onDelete: FK_ACTIONS[str(r.on_delete)] ?? "NO ACTION",
          onUpdate: FK_ACTIONS[str(r.on_update)] ?? "NO ACTION"
        };
    }
    if (str(r.table_schema) !== raw.schema) {
      if (c.kind === "foreign") {
        externalForeignKeys.push({ ...c, from: { schema: str(r.table_schema), table: str(r.table_name) } });
      }
      continue;
    }
    const list = constraintsByTable.get(str(r.table_name)) ?? [];
    list.push(c);
    constraintsByTable.set(str(r.table_name), list);
  }

  const grantsByRelation = new Map<string, Grant[]>();
  const pushGrant = (table: string, g: Grant) => {
    const list = grantsByRelation.get(table) ?? [];
    list.push(g);
    grantsByRelation.set(table, list);
  };
  for (const r of raw.tableGrants) {
    pushGrant(str(r.table_name), { grantee: str(r.grantee), privilege: str(r.privilege), columns: null });
  }
  // Group column-level privileges by (role, privilege)
  const colGrantKey = new Map<string, Grant>();
  for (const r of raw.columnGrants) {
    const key = `${str(r.table_name)}\u0000${str(r.grantee)}\u0000${str(r.privilege)}`;
    let g = colGrantKey.get(key);
    if (!g) {
      g = { grantee: str(r.grantee), privilege: str(r.privilege), columns: [] };
      colGrantKey.set(key, g);
      pushGrant(str(r.table_name), g);
    }
    g.columns?.push(str(r.column_name));
  }

  const tables: TableRules[] = raw.tables.map((r) => {
    const name = str(r.name);
    return {
      name,
      kind: r.relkind === "p" ? "partitioned" : "table",
      isPartition: Boolean(r.is_partition),
      rls: { enabled: Boolean(r.rls_enabled), forced: Boolean(r.rls_forced) },
      columns: columnsByTable.get(name) ?? [],
      policies: policiesByTable.get(name) ?? [],
      triggers: triggersByTable.get(name) ?? [],
      constraints: constraintsByTable.get(name) ?? [],
      grants: grantsByRelation.get(name) ?? []
    };
  });

  return { tables, externalForeignKeys, grantsByRelation };
}

export function assembleDocument(raw: RawCatalog): RulesDocument {
  const { tables, externalForeignKeys, grantsByRelation } = assembleTables(raw);
  const views: ViewRules[] = raw.views.map((r) => ({
    name: str(r.name),
    kind: r.relkind === "m" ? "materialized" : "view",
    securityInvoker: Boolean(r.security_invoker),
    securityBarrier: Boolean(r.security_barrier),
    definition: str(r.definition),
    baseRelations: strArray(r.base_relations).map((q) => {
      const dot = q.indexOf(".");
      return { schema: q.slice(0, dot), name: q.slice(dot + 1) };
    }),
    grants: grantsByRelation.get(str(r.name)) ?? []
  }));

  const functions: FunctionInfo[] = raw.functions.map((r) => ({
    name: str(r.name),
    identityArguments: str(r.identity_arguments),
    returns: str(r.returns),
    kind: r.prokind === "p" ? "procedure" : r.prokind === "a" ? "aggregate" : r.prokind === "w" ? "window" : "function",
    language: str(r.language),
    volatility: r.volatility === "i" ? "IMMUTABLE" : r.volatility === "s" ? "STABLE" : "VOLATILE",
    securityDefiner: Boolean(r.security_definer),
    searchPath: strOrNull(r.search_path),
    executableBy: { anon: Boolean(r.anon_execute), authenticated: Boolean(r.authenticated_execute) },
    definition: strOrNull(r.definition),
    comment: strOrNull(r.comment)
  }));
  const knownFunctions = new Set(functions.map((f) => f.name));
  for (const f of functions) f.analysis = analyzeFunction(f, raw.schema, knownFunctions);

  const platformEventTriggers: { name: string; reason: string }[] = [];
  const userEventTriggers: { name: string; owner: string }[] = [];
  for (const r of raw.eventTriggers) {
    if (r.extension_owned) platformEventTriggers.push({ name: str(r.name), reason: "owned by an extension" });
    else if (str(r.owner) === "supabase_admin") {
      platformEventTriggers.push({ name: str(r.name), reason: "owned by the Supabase platform (supabase_admin)" });
    } else userEventTriggers.push({ name: str(r.name), owner: str(r.owner) });
  }

  const doc: RulesDocument = {
    formatVersion: FORMAT_VERSION,
    generatedAt: raw.now.toISOString(),
    source: { schema: raw.schema, serverVersion: raw.serverVersion },
    roles: raw.roles.map((r) => ({
      name: str(r.name),
      bypassRls: Boolean(r.bypass_rls),
      superuser: Boolean(r.superuser)
    })),
    tables,
    views,
    functions,
    externalForeignKeys,
    eventTriggers: userEventTriggers,
    excluded: {
      extensionOwnedFunctions: raw.extensionOwnedFunctions,
      extensionOwnedRelations: raw.extensionOwnedRelations,
      eventTriggers: platformEventTriggers
    }
  };
  if (raw.storage) {
    doc.storage = assembleStorage(raw.storage);
    // Roles named only in storage policies are needed to compose the Storage cells
    for (const r of raw.storage.roles) {
      if (doc.roles.some((x) => x.name === str(r.name))) continue;
      doc.roles.push({ name: str(r.name), bypassRls: Boolean(r.bypass_rls), superuser: Boolean(r.superuser) });
    }
    doc.roles.sort((a, b) => a.name.localeCompare(b.name));
  }
  return doc;
}

const toLimit = (v: unknown): number | null => {
  if (v === null || v === undefined) return null;
  const n = Number(v);
  return Number.isSafeInteger(n) && n >= 0 ? n : null;
};

export function assembleStorage(raw: RawStorageCatalog): StorageRules {
  const { tables } = assembleTables({ ...raw, schema: STORAGE_SCHEMA });
  return {
    buckets: raw.buckets.map((r) => ({
      id: str(r.id),
      name: str(r.name),
      public: Boolean(r.public),
      fileSizeLimit: toLimit(r.file_size_limit),
      allowedMimeTypes: Array.isArray(r.allowed_mime_types) ? r.allowed_mime_types.map(String) : null
    })),
    bucketsReadable: raw.bucketsReadable,
    bucketsFiltered: raw.bucketsFiltered,
    objects: tables.find((t) => t.name === "objects") ?? null
  };
}
