/**
 * Types of rules.json (the output of extract and the input of render).
 * Keep in sync with schemas/rules.schema.json.
 */

export const FORMAT_VERSION = 1;

export const OPERATIONS = ["SELECT", "INSERT", "UPDATE", "DELETE"] as const;
export type Operation = (typeof OPERATIONS)[number];

export type TriggerEvent = "INSERT" | "UPDATE" | "DELETE" | "TRUNCATE";
export type PolicyCommand = Operation | "ALL";
export type FkAction = "NO ACTION" | "RESTRICT" | "CASCADE" | "SET NULL" | "SET DEFAULT";

export interface RulesDocument {
  formatVersion: typeof FORMAT_VERSION;
  generatedAt: string;
  source: {
    schema: string;
    serverVersion: string;
  };
  roles: RoleInfo[];
  tables: TableRules[];
  views: ViewRules[];
  functions: FunctionInfo[];
  /** Foreign keys from tables in other schemas that reference tables in the target schema. */
  externalForeignKeys: ExternalForeignKey[];
  /** Event triggers not owned by the platform (database-wide, shown for reference). */
  eventTriggers: { name: string; owner: string }[];
  excluded: ExcludedSummary;
  /**
   * Supabase Storage, extracted regardless of `source.schema`. Optional so that rules.json written by older versions
   * stays valid; absent when the storage schema does not exist.
   */
  storage?: StorageRules;
}

export interface StorageRules {
  buckets: BucketInfo[];
  /** False when the extracting role could not read storage.buckets; `buckets` is then empty. */
  bucketsReadable: boolean;
  /** Read through row security policies on storage.buckets: buckets hidden from the extracting role are missing. */
  bucketsFiltered: boolean;
  /** Rules of storage.objects (policies, triggers, constraints, GRANTs); null when the table does not exist. */
  objects: TableRules | null;
}

/** Settings of one row of storage.buckets (the only table rows the extractor reads). */
export interface BucketInfo {
  id: string;
  name: string;
  public: boolean;
  /** Bytes; null when no limit is set. */
  fileSizeLimit: number | null;
  /** null when every MIME type is allowed. */
  allowedMimeTypes: string[] | null;
}

export interface RoleInfo {
  name: string;
  bypassRls: boolean;
  superuser: boolean;
}

export interface TableRules {
  name: string;
  kind: "table" | "partitioned";
  isPartition: boolean;
  rls: { enabled: boolean; forced: boolean };
  columns: ColumnInfo[];
  policies: Policy[];
  triggers: Trigger[];
  constraints: Constraint[];
  grants: Grant[];
}

export interface ColumnInfo {
  name: string;
  type: string;
  notNull: boolean;
  default: string | null;
  identity: "ALWAYS" | "BY DEFAULT" | null;
  generated: boolean;
}

export interface Policy {
  name: string;
  command: PolicyCommand;
  permissive: boolean;
  /** "public" applies to every role. */
  roles: string[];
  using: string | null;
  withCheck: string | null;
}

export interface Trigger {
  name: string;
  timing: "BEFORE" | "AFTER" | "INSTEAD OF";
  level: "ROW" | "STATEMENT";
  events: TriggerEvent[];
  updateColumns: string[];
  when: string | null;
  function: { schema: string; name: string; securityDefiner: boolean };
  /** O=enabled / D=disabled / R=replica only / A=always */
  enabled: "O" | "D" | "R" | "A";
  isConstraintTrigger: boolean;
  definition: string;
}

export type Constraint =
  | { kind: "primary" | "unique" | "exclusion"; name: string; columns: string[]; definition: string }
  | { kind: "check"; name: string; columns: string[]; definition: string }
  | {
      kind: "foreign";
      name: string;
      columns: string[];
      references: { schema: string; table: string; columns: string[] };
      onDelete: FkAction;
      onUpdate: FkAction;
      definition: string;
    };

export type ForeignKeyConstraint = Extract<Constraint, { kind: "foreign" }>;

export interface ExternalForeignKey extends Omit<ForeignKeyConstraint, "kind"> {
  kind: "foreign";
  from: { schema: string; table: string };
}

export interface Grant {
  grantee: string;
  privilege: string;
  /** null for a table-level privilege, a column list for a column-level one. */
  columns: string[] | null;
}

export interface ViewRules {
  name: string;
  kind: "view" | "materialized";
  securityInvoker: boolean;
  securityBarrier: boolean;
  definition: string;
  baseRelations: { schema: string; name: string }[];
  grants: Grant[];
}

export interface FunctionInfo {
  name: string;
  identityArguments: string;
  returns: string;
  kind: "function" | "procedure" | "aggregate" | "window";
  language: string;
  volatility: "IMMUTABLE" | "STABLE" | "VOLATILE";
  securityDefiner: boolean;
  /** search_path from proconfig; null when not set. */
  searchPath: string | null;
  executableBy: { anon: boolean; authenticated: boolean };
  definition: string | null;
  /** COMMENT ON FUNCTION. Optional so that rules.json written by older versions stays valid. */
  comment?: string | null;
  /** Deterministic summary of the body (PL/pgSQL only). Optional for the same reason; render computes it when absent. */
  analysis?: FunctionAnalysis;
}

/** One enclosing branch on the way to a statement. `notTaken` lists earlier branches of the same IF / CASE that were false. */
export interface GuardPathElement {
  kind: "IF" | "ELSIF" | "ELSE" | "WHEN" | "LOOP" | "EXCEPTION WHEN";
  /** Condition text (null for ELSE). For a simple CASE, `subject` holds the CASE operand and `sql` the WHEN values. */
  sql: string | null;
  notTaken: string[];
  subject?: string;
  /** Comment block written directly above the IF statement. */
  comment?: string;
}

export interface Guard {
  /** Empty when the RAISE is unconditional. */
  path: GuardPathElement[];
  /** Format string of the RAISE (or MESSAGE option); null for a bare RAISE / condition name. */
  message: string | null;
  arguments: string | null;
  errcode: string | null;
  detail: string | null;
  hint: string | null;
  statement: string;
}

export interface EarlyReturn {
  path: GuardPathElement[];
  statement: string;
}

export interface SideEffect {
  operation: "INSERT" | "UPDATE" | "DELETE" | "MERGE" | "TRUNCATE" | "PERFORM";
  schema: string | null;
  name: string;
}

export interface FunctionAnalysis {
  /** analyzed: control flow followed; partial: some RAISE not placed; failed: control flow not followed; unsupported: not PL/pgSQL. */
  status: "analyzed" | "partial" | "failed" | "unsupported";
  reason: string | null;
  guards: Guard[];
  earlyReturns: EarlyReturn[];
  sideEffects: SideEffect[];
  newColumns: string[];
  oldColumns: string[];
  /** Columns compared between NEW and OLD with IS DISTINCT FROM / <> / !=. */
  changeCheckedColumns: string[];
  /** Functions of the target schema called from the body (bare names). */
  calledFunctions: string[];
  headerComments: string[];
  /** EXECUTE is present: dynamically built SQL is not analyzed. */
  dynamicSql: boolean;
  unparsedCount: number;
}

export interface ExcludedSummary {
  extensionOwnedFunctions: number;
  extensionOwnedRelations: number;
  eventTriggers: { name: string; reason: string }[];
}
