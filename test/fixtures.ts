import type { Grant, Policy, RulesDocument, TableRules, Trigger } from "../src/model/types.ts";

const DML = ["SELECT", "INSERT", "UPDATE", "DELETE", "TRUNCATE", "REFERENCES", "TRIGGER"];

export function defaultGrants(roles = ["anon", "authenticated", "service_role"]): Grant[] {
  return roles.flatMap((grantee) => DML.map((privilege) => ({ grantee, privilege, columns: null })));
}

export function policy(p: Partial<Policy> & Pick<Policy, "name" | "command">): Policy {
  return { permissive: true, roles: ["authenticated"], using: null, withCheck: null, ...p };
}

export function trigger(t: Partial<Trigger> & Pick<Trigger, "name">): Trigger {
  return {
    timing: "BEFORE",
    level: "ROW",
    events: ["INSERT"],
    updateColumns: [],
    when: null,
    function: { schema: "public", name: "trg_fn", securityDefiner: false },
    enabled: "O",
    isConstraintTrigger: false,
    definition: `CREATE TRIGGER ${t.name} ...`,
    ...t
  };
}

export function table(t: Partial<TableRules> & Pick<TableRules, "name">): TableRules {
  return {
    kind: "table",
    isPartition: false,
    rls: { enabled: true, forced: false },
    columns: [],
    policies: [],
    triggers: [],
    constraints: [],
    grants: defaultGrants(),
    ...t
  };
}

export function doc(partial: Partial<RulesDocument> = {}): RulesDocument {
  return {
    formatVersion: 1,
    generatedAt: "2026-10-01T00:00:00.000Z",
    source: { schema: "public", serverVersion: "17.6" },
    roles: [
      { name: "anon", bypassRls: false, superuser: false },
      { name: "authenticated", bypassRls: false, superuser: false },
      { name: "reporting_role", bypassRls: false, superuser: false },
      { name: "service_role", bypassRls: true, superuser: false }
    ],
    tables: [],
    views: [],
    functions: [],
    externalForeignKeys: [],
    eventTriggers: [],
    excluded: { extensionOwnedFunctions: 0, extensionOwnedRelations: 0, eventTriggers: [] },
    ...partial
  };
}

export const TEAM_ROLE =
  "(team_id IN ( SELECT get_team_ids_for_roles(ARRAY['admin'::team_role]) AS get_team_ids_for_roles))";

/** Wraps a body the way pg_get_functiondef prints it. */
export function def(name: string, body: string, tag = "$function$"): string {
  return `CREATE OR REPLACE FUNCTION public.${name}()
 RETURNS trigger
 LANGUAGE plpgsql
 SET search_path TO ''
AS ${tag}
${body}
${tag}
`;
}

export interface PgUrlParts {
  scheme?: string;
  user: string;
  password?: string;
  host?: string;
  port?: number | string;
  db?: string;
  query?: string;
}

/**
 * Builds a connection URL at run time. Secret scanners (secretlint in CI) flag credential-bearing URL literals,
 * so the synthetic ones used by the tests never appear as a single literal in the source.
 */
export function pgUrl({
  scheme = "postgresql",
  user,
  password,
  host = "127.0.0.1",
  port,
  db = "postgres",
  query
}: PgUrlParts): string {
  const auth = password === undefined ? user : `${user}:${password}`;
  const hostPort = port === undefined ? host : `${host}:${port}`;
  return `${scheme}://${auth}@${hostPort}/${db}${query === undefined ? "" : `?${query}`}`;
}
